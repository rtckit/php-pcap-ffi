<?php

namespace RTCKit\Pcap\Stream\FFI;

use FFI\CData;

/**
 * Stream wrapper for pcap protocol
 */
class StreamWrapper
{
    private static ?PcapFFI $pcapFFI = null;

    private ?string $dev = null;

    private ?string $mode = null;

    private ?int $fd = null;
    private $fp = null;

    private string $buffer = '';

    private array $options = [
        'snaplen' => 65536,
        'promisc' => 0,
        'immediate' => 0,
        'timeout' => 1000,
        'non_blocking' => 0,
        'filter' => '',
    ];

    private ?CData $pcap = null;

    private function closeSession(): void {
        if (!is_null($this->pcap)) {
            self::$pcapFFI->close($this->pcap);
        }

        if (!is_null($this->fp)) {
            fclose($this->fp);
        }
    }

    private function activateSession(): ?CData {
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

        $pcap = self::$pcapFFI->create($this->dev);

        if (is_null($pcap)) {
            $this->fail("Cannot initiate capture on device {$this->dev}:" . self::$pcapFFI->getLastError());
            $this->closeSession();

            return null;
        }

        if (self::$pcapFFI->set_snaplen($pcap, $this->options['snaplen']) < 0) {
            $this->fail("Cannot set snapshot length {$this->options['snaplen']} on device {$this->dev}");
        }

        if ($this->options['promisc'] && (self::$pcapFFI->set_promisc($pcap, $this->options['promisc']) < 0)) {
            $this->fail("Cannot set promiscuous mode {$this->options['promisc']} on device {$this->dev}");
        }

        if ($this->options['immediate'] && (self::$pcapFFI->set_immediate_mode($pcap, $this->options['immediate']) < 0)) {
            $this->fail("Cannot set immediate mode {$this->options['immediate']} on device {$this->dev}");
        }

        if (self::$pcapFFI->set_timeout($pcap, $this->options['timeout']) < 0) {
            $this->fail("Cannot set timeout {$this->options['timeout']}ms on device {$this->dev}");
        }

        if ($this->options['non_blocking'] && (self::$pcapFFI->setnonblock($pcap, $this->options['non_blocking']) < 0)) {
            $this->fail("Cannot set blocking option on device {$this->dev}: " . self::$pcapFFI->getLastError());
        }

        if (self::$pcapFFI->activate($pcap) < 0) {
            $this->fail("Cannot activate live capture on device {$this->dev}: " . self::$pcapFFI->getLastError());
            $this->closeSession();

            return null;
        }

        if (strlen($this->options['filter']) && (self::$pcapFFI->compile_setfilter($pcap, $this->options['filter']) < 0)) {
            $this->fail("Cannot set filter option on device {$this->dev}: " . self::$pcapFFI->getLastError());
        }

        $this->pcap = $pcap;

        return $this->pcap;
    }

    public function stream_read(int $count): string {
        if (is_null($this->pcap) && is_null($this->activateSession())) {
            return '';
        }

        $ret = '';
        $bytes = $this->buffer;
        $length = strlen($this->buffer);

        while ($count) {
            if (!$length) {
                $bytes = self::$pcapFFI->next_ex($this->pcap);
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

    public function stream_open(string $path, string $mode, ?int $options, ?string &$opened_path): bool {
        if (is_null(self::$pcapFFI)) {
            self::$pcapFFI = new PcapFFI();
        }

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
        $devs = self::$pcapFFI->findalldevs();

        if (is_null($devs)) {
            $this->fail('Cannot enumerate network devices: ' . self::$pcapFFI->getLastError());

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

    public function stream_close(): void {
    }

    public function stream_cast(int $cast_as) {
        if (is_null($this->pcap) && is_null($this->activateSession())) {
            return false;
        }

        switch ($cast_as) {
            case STREAM_CAST_FOR_SELECT:
            case STREAM_CAST_AS_STREAM:
                $fd = self::$pcapFFI->get_selectable_fd($this->pcap);

                if ($fd < 0) {
                    return false;
                }

                $fp = fopen("php://fd/{$fd}", $this->mode);

                if (!$fp) {
                    return false;
                }

                $this->fd = $fd;
                $this->fp = $fp;

                return $this->fp;
        }

        return false;
    }

    public function stream_eof(): bool {
        return false;
    }

    private function fail(string $message): void {
       trigger_error($message, E_USER_WARNING);
    }
}
