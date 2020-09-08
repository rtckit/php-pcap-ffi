<?php

declare(strict_types = 1);

namespace RTCKit\Pcap\Stream\FFI;

use FFI\CData;

/**
 * Stream wrapper for pcap protocol
 */
class StreamWrapper
{
    public const MIN_LIBPCAP_VERSION = '1.8.0';

    private PcapFFI $pcapFFI;

    private string $dev = '';

    private string $mode = '';

    /**
     * Resource handle, useful for stream multiplexing operations.
     * Note the property is not typed, here's why
     * - https://wiki.php.net/rfc/resource_typehint
     * - https://bugs.php.net/bug.php?id=71518
     *
     * @var ?resource
     */
    private $fp = null;

    private string $buffer = '';

    /**
     * Various libpcap properties, set at session level.
     *
     * @var array<mixed>
     */
    private array $options = [
        'snaplen' => 65536,
        'promisc' => 0,
        'immediate' => 0,
        'timeout' => 1000,
        'non_blocking' => 0,
        'filter' => '',
    ];

    private ?CData $pcap = null;

    public function __construct()
    {
        $this->pcapFFI = new PcapFFI();
        $version = $this->pcapFFI->lib_version();

        if (preg_match('/libpcap version ([\d\.]+)(.*)/', $version, $matches) === 1) {
            if (!version_compare($matches[1], self::MIN_LIBPCAP_VERSION, '>=')) {
                $this->fail('Please upgrade libpcap to a higher version (>= ' . self::MIN_LIBPCAP_VERSION . ')');

                return false;
            }
        } else {
            $this->fail('Cannot reliably determine libpcap version');
        }
    }

    private function closeSession(): void
    {
        if (!is_null($this->pcap)) {
            $this->pcapFFI->close($this->pcap);
            $this->pcap = null;
        }

        if (!is_null($this->fp)) {
            fclose($this->fp);
            $this->fp = null;
        }
    }

    private function activateSession(): ?CData
    {
        if (isset($this->context)) {
            $context = stream_context_get_options($this->context);

            if (!empty($context['pcap']) && is_array($context['pcap'])) {
                if (isset($context['pcap']['snaplen']) && is_int($context['pcap']['snaplen'])) {
                    $this->options['snaplen'] = $context['pcap']['snaplen'];
                }

                if (isset($context['pcap']['promisc']) && is_bool($context['pcap']['promisc'])) {
                    $this->options['promisc'] = $context['pcap']['promisc'] ? 1 : 0;
                }

                if (isset($context['pcap']['immediate']) && is_bool($context['pcap']['immediate'])) {
                    $this->options['immediate'] = $context['pcap']['immediate'] ? 1 : 0;
                }

                if (isset($context['pcap']['blocking']) && is_bool($context['pcap']['blocking'])) {
                    $this->options['non_blocking'] = $context['pcap']['blocking'] ? 0 : 1;
                }

                if (isset($context['pcap']['timeout']) && is_float($context['pcap']['timeout'])) {
                    $this->options['timeout'] = (int) ($context['pcap']['timeout'] * 1000);
                }

                if (isset($context['pcap']['filter']) && is_string($context['pcap']['filter']) && strlen($context['pcap']['filter'])) {
                    $this->options['filter'] = $context['pcap']['filter'];
                }
            }
        }

        $pcap = $this->pcapFFI->create($this->dev);

        if (is_null($pcap)) {
            $this->fail("Cannot initiate capture on device {$this->dev}:" . $this->pcapFFI->getLastError());
            $this->closeSession();

            return null;
        }

        if ($this->pcapFFI->set_snaplen($pcap, $this->options['snaplen']) < 0) {
            $this->fail("Cannot set snapshot length {$this->options['snaplen']} on device {$this->dev}");
        }

        if ($this->options['promisc'] && ($this->pcapFFI->set_promisc($pcap, $this->options['promisc']) < 0)) {
            $this->fail("Cannot set promiscuous mode {$this->options['promisc']} on device {$this->dev}");
        }

        if ($this->options['immediate'] && ($this->pcapFFI->set_immediate_mode($pcap, $this->options['immediate']) < 0)) {
            $this->fail("Cannot set immediate mode {$this->options['immediate']} on device {$this->dev}");
        }

        if ($this->pcapFFI->set_timeout($pcap, $this->options['timeout']) < 0) {
            $this->fail("Cannot set timeout {$this->options['timeout']}ms on device {$this->dev}");
        }

        if ($this->options['non_blocking'] && ($this->pcapFFI->setnonblock($pcap, $this->options['non_blocking']) < 0)) {
            $this->fail("Cannot set blocking option on device {$this->dev}: " . $this->pcapFFI->getLastError());
        }

        if ($this->pcapFFI->activate($pcap) < 0) {
            $this->fail("Cannot activate live capture on device {$this->dev}: " . $this->pcapFFI->getLastError());
            $this->closeSession();

            return null;
        }

        if (strlen($this->options['filter']) && ($this->pcapFFI->compile_setfilter($pcap, $this->options['filter']) < 0)) {
            $this->fail("Cannot set filter option on device {$this->dev}: " . $this->pcapFFI->getLastError());
        }

        $this->pcap = $pcap;

        return $this->pcap;
    }

    public function stream_write(string $data): int
    {
        if (is_null($this->pcap) && is_null($this->activateSession())) {
            return -1;
        }

        $ret = $this->pcapFFI->inject($this->pcap, $data);

        if ($ret < 0) {
            $this->fail("Cannot write to device {$this->dev}: " . $this->pcapFFI->getLastError());
        }

        return $ret;
    }

    public function stream_read(int $count): string
    {
        if (is_null($this->pcap) && is_null($this->activateSession())) {
            return '';
        }

        $ret = '';
        $bytes = $this->buffer;
        $length = strlen($this->buffer);

        while ($count) {
            if (!$length) {
                $bytes = $this->pcapFFI->next_ex($this->pcap);
                $length = strlen($bytes);

                if (!$length) {
                    break;
                }
            }

            $copy = min($count, $length);
            $ret .= substr($bytes, 0, $copy);
            $this->buffer = substr($bytes, $copy);
            $count -= $copy;
            $length -= $copy;
        }

        return $ret;
    }

    public function stream_open(string $path, string $mode, ?int $options, ?string &$opened_path): bool
    {
        if (extension_loaded('sockets')) {
            $raw = @\socket_create(AF_INET, SOCK_RAW, SOL_TCP);

            if ($raw === false) {
                $this->fail('Cannot open raw sockets (check privileges or CAP_NET_RAW capability)');

                return false;
            }

            \socket_close($raw);
        }

        $url = parse_url($path);

        if (!$url) {
            $this->fail('Cannot parse pcap path');

            return false;
        }

        if (!isset($url['host'])) {
            $this->fail('Missing device name!');

            return false;
        }

        if (!isset($url['scheme']) || ($url['scheme'] !== 'pcap')) {
            $this->fail('Unsupported scheme (should be pcap)');
        }

        if (isset($url['path']) && ($url['path'] !== '/')) {
            $this->fail(sprintf('Unsupported path: %s', $url['path']));
        }

        if (isset($url['query'])) {
            $this->fail(sprintf('Unsupported query: %s', $url['query']));
        }

        $this->dev = $url['host'];

        $this->mode = $mode;

        $found = false;
        $devs = $this->pcapFFI->findalldevs();

        if (is_null($devs)) {
            $this->fail('Cannot enumerate network devices: ' . $this->pcapFFI->getLastError());

            return false;
        }

        foreach ($devs as $dev) {
            if ($dev['name'] == $this->dev) {
                $found = true;
                break;
            }
        }

        if (!$found) {
            $this->fail(sprintf('Unknown device: %s', $this->dev));
        }

        return true;
    }

    public function stream_close(): void
    {
    }

    /**
     * @return resource|false
     */
    public function stream_cast(int $cast_as)
    {
        if (is_null($this->pcap) && is_null($this->activateSession())) {
            return false;
        }

        switch ($cast_as) {
            case STREAM_CAST_FOR_SELECT:
            case STREAM_CAST_AS_STREAM:
                if (!is_null($this->fp)) {
                    return $this->fp;
                }

                $fd = $this->pcapFFI->get_selectable_fd($this->pcap);

                if ($fd < 0) {
                    return false;
                }

                $fp = fopen("php://fd/{$fd}", $this->mode);

                if (!$fp) {
                    return false;
                }

                $this->fp = $fp;

                stream_set_blocking($this->fp, $this->options['non_blocking'] == 0);
                stream_set_timeout($this->fp, (int) floor($this->options['timeout'] / 1000), ($this->options['timeout'] % 1000) * 1000);

                if ($this->options['immediate'] === 1) {
                    stream_set_read_buffer($this->fp, 0);
                }

                return $this->fp;
        }

        return false;
    }

    public function stream_eof(): bool
    {
        return false;
    }

    private function fail(string $message): void
    {
       trigger_error($message, E_USER_WARNING);
    }
}
