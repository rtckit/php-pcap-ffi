<?php

namespace RTCKit\Pcap\Stream\FFI;

class IPv4UdpDnsTest extends \PHPUnit\Framework\TestCase {
    public const NAMESERVER = '208.67.222.222';
    public const FQDN = 'example.com';

    /** @test */
    public function shouldCaptureIPv4UdpDnsTraffic() {
        $context = stream_context_create([
            'pcap' => [
                'snaplen'   => 2048,
                'immediate' => true,
                'timeout'   => 0.100,
                'filter'    => 'host ' . self::NAMESERVER,
            ],
        ]);

        $fp = fopen('pcap://any', 'r', false, $context);

        $this->assertIsResource($fp);

        // Trigger capture activation, expect nothing to read
        $body = fread($fp, 16);

        $this->assertIsString($body);
        $this->assertEmpty($body);

        // Fire the DNS queries we want to sniff
        $this->execDig();

        $captures = [$fp];
        $read = [];
        $write = $except = null;

        $localMac = '';
        $remoteMac = '';
        $ipv4Request = false;
        $ipv4Response = false;
        $ipv4Addr = '';
        $ipv6Request = false;
        $ipv6Response = false;
        $ipv6Addr = '';
        $replies = 0;

        $startedAt = time();

        while (!$ipv4Request || !$ipv4Response || !$ipv6Request || !$ipv6Response) {
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

                            if ($ipv4['protocol'] === 17) { // UDP
                                $udp = parseUDPFrame($ipv4['data']);

                                if(($udp['srcPort'] == 53) || ($udp['dstPort'] == 53)) { // DNS
                                    $dns = parseDNSMesage($udp['data']);

                                    if ($dns['qr'] === false) { // Query
                                        if ($dns['queries'][0]['type'] === 1) { // A
                                            $ipv4Request = true;
                                            echo "A DNS query for {$dns['queries'][0]['name']}\n";
                                        } elseif ($dns['queries'][0]['type'] === 28) { // AAAA
                                            $ipv6Request = true;
                                            echo "AAAA DNS query for {$dns['queries'][0]['name']}\n";
                                        }
                                    } else { // Answer
                                        if ($dns['answers'][0]['type'] === 1) { // A
                                            $ipv4Response = true;
                                            $ipv4Addr = $dns['answers'][0]['address'];
                                            echo "A DNS reply for {$dns['queries'][0]['name']}: {$dns['answers'][0]['address']} TTL={$dns['answers'][0]['ttl']}\n";
                                        } elseif ($dns['answers'][0]['type'] === 28) { // AAAA
                                            $ipv6Response = true;
                                            $ipv6Addr = $dns['answers'][0]['address'];
                                            echo "AAAA DNS reply for {$dns['queries'][0]['name']}: {$dns['answers'][0]['address']} TTL={$dns['answers'][0]['ttl']}\n";
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        $this->assertTrue($ipv4Request);
        $this->assertTrue($ipv4Response);
        $this->assertTrue($ipv6Request);
        $this->assertTrue($ipv6Response);

        $this->assertEquals($ipv4Addr, filter_var($ipv4Addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4));
        $this->assertEquals($ipv6Addr, filter_var($ipv6Addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6));

        $this->assertEquals($localMac, filter_var($localMac, FILTER_VALIDATE_MAC));
        $this->assertEquals($remoteMac, filter_var($remoteMac, FILTER_VALIDATE_MAC));
    }

    private function execDig(): void {
        shell_exec("sleep 0 && dig @" . self::NAMESERVER . " " . self::FQDN . " A 2>/dev/null >/dev/null &");
        shell_exec("sleep 1 && dig @" . self::NAMESERVER . " " . self::FQDN . " AAAA 2>/dev/null >/dev/null &");
    }
}
