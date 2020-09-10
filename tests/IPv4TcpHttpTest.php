<?php

declare(strict_types = 1);

namespace RTCKit\Pcap\Stream\FFI;

class IPv4TcpHttpTest extends \PHPUnit\Framework\TestCase {
    public const HOSTNAME = 'example.com';
    public const USER_AGENT = 'PHP Pcap Extension Tester';

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

        // Fire the HTTP request we want to sniff
        $this->execCurl();

        $captures = [$fp];
        $read = [];
        $write = $except = null;

        $localMac = '';
        $remoteMac = '';
        $foundRequest = false;
        $foundResponse = false;
        $requestHost = '';
        $requestUserAgent = '';
        $requestAccepts = '';
        $responseContentType = '';
        $responseDate = '';
        $responseContentLength = '';

        $startedAt = time();

        while (!$foundRequest || !$foundResponse) {
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

                            if ($ipv4['protocol'] === 6) { // TCP
                                $tcp = parseTCPSegment($ipv4['data']);

                                // Test for our HTTP request
                                if (!$foundRequest && ($ipv4['dstAddr'] === $this->ip) && ($tcp['dstPort'] === 80) && strlen($tcp['data'])) {
                                    $lines = explode("\r\n", $tcp['data']);

                                    if (isset($lines[0]) && ($lines[0] === 'GET / HTTP/1.1')) {
                                        $foundRequest = true;

                                        foreach ($lines as $line) {
                                            if (strpos($line, 'Host:') === 0) {
                                                var_dump($line);
                                                $requestHost = $line;
                                                continue;
                                            }

                                            if (strpos($line, 'User-Agent:') === 0) {
                                                var_dump($line);
                                                $requestUserAgent = $line;
                                                continue;
                                            }

                                            if (strpos($line, 'Accept:') === 0) {
                                                var_dump($line);
                                                $requestAccepts = $line;
                                                continue;
                                            }
                                        }
                                    }
                                }

                                // Test for remote HTTP response segment
                                if (!$foundResponse && ($ipv4['srcAddr'] === $this->ip) && ($tcp['srcPort'] === 80) && strlen($tcp['data'])) {
                                    $lines = explode("\r\n", $tcp['data']);

                                    if (isset($lines[0]) && ($lines[0] === 'HTTP/1.1 200 OK')) {
                                        $foundResponse = true;

                                        foreach ($lines as $line) {
                                            if (strpos($line, 'Content-Type:') === 0) {
                                                var_dump($line);
                                                $responseContentType = $line;
                                                continue;
                                            }

                                            if (strpos($line, 'Date:') === 0) {
                                                var_dump($line);
                                                $responseDate = $line;
                                                continue;
                                            }

                                            if (strpos($line, 'Content-Length:') === 0) {
                                                var_dump($line);
                                                $responseContentLength = $line;
                                                continue;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        $this->assertTrue($foundRequest);
        $this->assertTrue($foundResponse);

        $this->assertEquals('Host: ' . self::HOSTNAME, $requestHost);
        $this->assertEquals('User-Agent: ' . self::USER_AGENT, $requestUserAgent);
        $this->assertEquals('Accept: text/html', $requestAccepts);
        $this->assertEquals('Content-Type: text/html; charset=UTF-8', $responseContentType);

        $timestamp = explode(':', $responseDate, 2)[1];

        $this->assertTrue(time() - (new \DateTime($timestamp))->getTimestamp() <= 60);

        $length = (int) explode(':', $responseContentLength, 2)[1];

        $this->assertGreaterThan(0, $length);

        $this->assertEquals($localMac, filter_var($localMac, FILTER_VALIDATE_MAC));
        $this->assertEquals($remoteMac, filter_var($remoteMac, FILTER_VALIDATE_MAC));
    }

    private function resolveHostname(): void {
        $this->ip = gethostbyname(self::HOSTNAME);

        $this->assertNotEquals($this->ip, self::HOSTNAME);
    }

    private function execCurl(): void {
        shell_exec("curl http://{$this->ip}/ -H 'Host: example.com' -H 'User-Agent: " . self::USER_AGENT . "' -H 'Accept: text/html' 2>/dev/null >/dev/null &");
    }
}
