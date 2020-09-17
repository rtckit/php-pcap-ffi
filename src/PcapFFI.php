<?php

declare(strict_types = 1);

namespace RTCKit\Pcap\Stream\FFI;

use FFI;
use FFI\CData;
use FFI\Exception;

/**
 * FFI/libpcap class
 */
class PcapFFI
{
    public const LIBPCAP_NAME = 'libpcap.so.1';

    static private $ffi = NULL;

    private ?string $error = null;

    public function __construct()
    {
        if (self::$ffi) {
            return;
        }

        $lib = getenv('LIBPCAP_NAME');
        if ($lib) {
            // old way
            $code = file_get_contents(__DIR__ . '/pcap.h');

            if ($code === false) {
                throw new Exception('Cannot load pcap C definitions');
            }
            self::$ffi = FFI::cdef($code, $lib);
        } else {
            try {
                // Try preload
                self::$ffi = \FFI::scope("_RTCKIT_PCAP_FFI_");
            } catch (\FFI\Exception $e) {
                // Try direct load
                self::$ffi = \FFI::load(__DIR__ . '/pcap.h');
            }
        }
        if (!self::$ffi) {
            throw new \RuntimeException("FFI parse fails");
        }
    }

    public function lib_version(): string
    {
        return self::$ffi->pcap_lib_version();
    }

    /**
     * Returns an array of sniffable network interfaces. The output might differ
     * from PHP's net_get_interfaces() as it's reflecting libpcap's perspective.
     *
     * @return ?array<mixed>
     */
    public function findalldevs(): ?array
    {
        $this->resetLastError();

        $devs = self::$ffi->new('pcap_if_t *');
        $dev = self::$ffi->new('pcap_if_t *');
        $err = self::$ffi->new('char[257]');

        if (self::$ffi->pcap_findalldevs(FFI::addr($devs), $err) < 0) {
            $this->setLastError(FFI::string($err));

            return null;
        }

        $ret = [];
        $dev = $devs;

        while (!is_null($dev)) {
            $ret[] = [
                'name' => FFI::string($dev->name),
            ];

            $dev = $dev->next;
        }

        self::$ffi->pcap_freealldevs($devs);

        return $ret;
    }

    public function create(string $dev): ?CData
    {
        $this->resetLastError();

        $err = self::$ffi->new('char[257]');
        $ret = self::$ffi->pcap_create($dev, $err);

        if (is_null($ret)) {
            $this->setLastError(FFI::string($err));

            return null;
        }

        return $ret;
    }

    public function set_snaplen(CData $pcap, int $snaplen): int
    {
        $this->resetLastError();

        $ret = self::$ffi->pcap_set_snaplen($pcap, $snaplen);

        if ($ret < 0) {
            $this->setLastPcapError($pcap);
        }

        return $ret;
    }

    public function set_promisc(CData $pcap, int $promisc): int
    {
        $this->resetLastError();

        $ret = self::$ffi->pcap_set_promisc($pcap, $promisc);

        if ($ret < 0) {
            $this->setLastPcapError($pcap);
        }

        return $ret;
    }

    public function set_immediate_mode(CData $pcap, int $immediate_mode): int
    {
        $this->resetLastError();

        $ret = self::$ffi->pcap_set_immediate_mode($pcap, $immediate_mode);

        if ($ret < 0) {
            $this->setLastPcapError($pcap);
        }

        return $ret;
    }

    public function set_timeout(CData $pcap, int $to_ms): int
    {
        $this->resetLastError();

        $ret = self::$ffi->pcap_set_timeout($pcap, $to_ms);

        if ($ret < 0) {
            $this->setLastPcapError($pcap);
        }

        return $ret;
    }

    public function setnonblock(CData $pcap, int $nonblock): int
    {
        $this->resetLastError();

        $err = self::$ffi->new('char[257]');
        $ret = self::$ffi->pcap_setnonblock($pcap, $nonblock, $err);

        if ($ret < 0) {
            $this->setLastError(FFI::string($err));
        }

        return $ret;
    }

    public function activate(CData $pcap): int
    {
        $this->resetLastError();

        $ret = self::$ffi->pcap_activate($pcap);

        if ($ret < 0) {
            $this->setLastPcapError($pcap);
        }

        return $ret;
    }

    public function get_selectable_fd(CData $pcap): int
    {
        return self::$ffi->pcap_get_selectable_fd($pcap);
    }

    public function inject(CData $pcap, string $data): int
    {
        return self::$ffi->pcap_inject($pcap, $data, strlen($data));
    }

    public function next_ex(CData $pcap): string
    {
        $this->resetLastError();

        $header = self::$ffi->new('struct pcap_pkthdr *');
        $data = self::$ffi->new('const u_char *');
        $next = self::$ffi->pcap_next_ex($pcap, FFI::addr($header), FFI::addr($data));

        if ($next < 0) {
            $this->setLastPcapError($pcap);
            return '';
        } else if (!$next) {
            return '';
        }

        $ret = pack('LLLL', $header[0]->ts->tv_sec, $header[0]->ts->tv_usec, $header[0]->caplen, $header[0]->len);
        $ret .= FFI::string($data, $header[0]->caplen);

        return $ret;
    }

    public function compile_setfilter(CData $pcap, string $filter): int
    {
        $this->resetLastError();

        $fp = self::$ffi->new('struct bpf_program');
        $ret = self::$ffi->pcap_compile($pcap, FFI::addr($fp), $filter, 0, 0);

        if ($ret < 0) {
            $this->setLastPcapError($pcap);
        } else {
            $ret = self::$ffi->pcap_setfilter($pcap, FFI::addr($fp));

            if ($ret < 0) {
                $this->setLastPcapError($pcap);
            }
        }

        return $ret;
    }

    public function close(CData $pcap): void
    {
        self::$ffi->pcap_close($pcap);
    }

    public function getLastError(): string
    {
        return is_null($this->error) ? '<unknown error>' : $this->error;
    }

    private function setLastError(string $error): void
    {
        $this->error = $error;
    }

    private function setLastPcapError(CData $pcap): void
    {
        $err = self::$ffi->pcap_geterr($pcap);

        if (!is_null($err)) {
            $this->setLastError(FFI::string($err));
        }
    }

    private function resetLastError(): void
    {
        $this->error = null;
    }
}
