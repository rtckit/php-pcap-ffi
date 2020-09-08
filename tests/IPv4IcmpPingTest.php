<?php

namespace RTCKit\Pcap\Stream\FFI;

class IPv4IcmpPingTest extends \PHPUnit\Framework\TestCase {
    public const HOSTNAME = 'example.com';
    public const COUNT = 4;

    private string $ip = '';

    /** @test */
    public function shouldCaptureIPv4IcmpPingTraffic() {
        $this->resolveHostname();

        $context = stream_context_create([
            'pcap' => [
                'snaplen'   => 2048,
                'immediate' => true,
                'timeout'   => 0.100,
                'filter'    => 'host ' . $this->ip,
            ],
        ]);

        $fp = fopen('pcap://any', 'r', false, $context);

        $this->assertIsResource($fp);

        // Trigger capture activation, expect nothing to read
        $body = fread($fp, 16);

        $this->assertIsString($body);
        $this->assertEmpty($body);

        // Fire the ping requests we want to sniff
        $this->execPing();

        $captures = [$fp];
        $read = [];
        $write = $except = null;

        $localMac = '';
        $remoteMac = '';
        $requests = 0;
        $replies = 0;

        $startedAt = time();

        while (($requests < self::COUNT) || ($replies < self::COUNT)) {
            $read = $captures;

            if (stream_select($read, $write, $except, 0, 100000)) {
                foreach ($read as $r) {
                    while ($_header = fread($r, 16)) {
                        $header = unpack('LtsSec/LtsUsec/LcapLen/Llen', $_header);
                        $frame = parseLinuxSLLFrame(fread($r, $header['capLen']));

                        if ($frame['packetType'] === 0) {
                            $remoteMac = $frame['address'];
                        }

                        if ($frame['packetType'] === 4) {
                            $localMac = $frame['address'];
                        }

                        if ($frame['etherType'] === 8) { // IPv4
                            $ipv4 = parseIPv4Frame($frame['data']);

                            if ($ipv4['protocol'] === 1) { // ICMP
                                $icmp = parseICMPFrame($ipv4['data']);

                                if($icmp['type'] === 8) {
                                    echo "Ping {$ipv4['srcAddr']} -> {$ipv4['dstAddr']}\n";
                                    $requests++;
                                }

                                if($icmp['type'] === 0) {
                                    echo "Pong {$ipv4['srcAddr']} -> {$ipv4['dstAddr']}\n";
                                    $replies++;
                                }
                            }
                        }
                    }
                }
            }
        }

        $this->assertEquals(self::COUNT, $requests);
        $this->assertEquals(self::COUNT, $replies);

        $this->assertEquals($localMac, filter_var($localMac, FILTER_VALIDATE_MAC));
        $this->assertEquals($remoteMac, filter_var($remoteMac, FILTER_VALIDATE_MAC));
    }

    private function resolveHostname(): void {
        $this->ip = gethostbyname(self::HOSTNAME);

        $this->assertNotEquals($this->ip, self::HOSTNAME);
    }

    private function execPing(): void {
        shell_exec("ping -c " . self::COUNT . " {$this->ip} 2>/dev/null >/dev/null &");
    }
}
