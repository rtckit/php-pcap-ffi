<?php

declare(strict_types = 1);

namespace RTCKit\Pcap\Stream\FFI;

class ArpIPv4Test extends \PHPUnit\Framework\TestCase {
    private string $dev = '';
    private string $myMac = '';
    private string $myIp = '';
    private string $gwIp = '';

    /** @test */
    public function shouldCaptureIPv4IcmpPingTraffic() {
        $this->findTestDevice();

        $context = stream_context_create([
            'pcap' => [
                'snaplen'   => 2048,
                'immediate' => true,
                'timeout'   => 0.100,
                'filter'    => 'arp',
            ],
        ]);

        $fp = fopen('pcap://' . $this->dev, 'rw', false, $context);
        $this->assertIsResource($fp);

        // Trigger capture activation, expect nothing to read
        $body = fread($fp, 16);

        $this->assertIsString($body);
        $this->assertEmpty($body);

        $packet = $this->craftWireArpPacket();

        $bytes = fwrite($fp, $packet);

        $this->assertIsNumeric($bytes);
        $this->assertEquals(strlen($packet), $bytes);

        $captures = [$fp];
        $read = [];
        $write = $except = null;

        $gwMac = null;

        while (!$gwMac) {
            $read = $captures;

            if (stream_select($read, $write, $except, 0, 100000)) {
                foreach ($read as $r) {
                    while ($_header = fread($r, 16)) {
                        $header = unpack('LtsSec/LtsUsec/LcapLen/Llen', $_header);
                        $frame = parseEthernet2Frame(fread($r, $header['capLen']));

                        if ($frame['etherType'] == 0x0806) { // ARP
                            $arp = parseArpFrame($frame['data']);

                            if (
                                ($arp['opcode'] == 2) // Response
                                && ($arp['senderProtoAddress'] == $this->gwIp) // Coming from Gateway
                                && ($arp['targetProtoAddress'] == $this->myIp) // Meant for our IPv4 address
                                && ($arp['targetEtherAddress'] == $this->myMac) // Meant for our hardware address
                            ) {
                                $gwMac = $arp['senderEtherAddress'];
                                break;
                            }
                        }
                    }
                }
            }
        }

        $this->assertNotNull($gwMac);
        $this->assertIsString($gwMac);
        $this->assertEquals($gwMac, filter_var($gwMac, FILTER_VALIDATE_MAC));
    }

    private function findTestDevice(): void {
        foreach (getRoutingTable() as $record) {
            if (!empty($record['Iface']) && !empty($record['Gateway']) && ($record['Gateway'] !== '00000000')) {
                $this->dev = $record['Iface'];
                $hex = $record['Gateway'];
                $gw = [];

                while (strlen($hex)) {
                    $byte = hexdec(substr($hex, -2));
                    $hex = substr($hex, 0, -2);
                    $gw[] = $byte;
                }

                $this->gwIp = implode('.', $gw);
                break;
            }
        }

        $this->assertNotEmpty($this->dev);

        $this->myMac = trim(file_get_contents('/sys/class/net/' . $this->dev . '/address'));

        $this->assertNotEmpty($this->myMac);

        foreach (net_get_interfaces()[$this->dev]['unicast'] as $config) {
            if ($config['family'] == 2) {
                $this->myIp = $config['address'];
                break;
            }
        }

        $this->assertNotEmpty($this->myIp);
    }

    private function craftWireArpPacket(): string {
        return craftEthernet2Frame([
            'destination' => 'ff:ff:ff:ff:ff:ff',
            'source' => $this->myMac,
            'etherType' => 0x0806, // ARP
            'data' => craftArpFrame([
                'htype' => 1, // Ethernet
                'ptype' => 0x0800, // IPv4
                'hsize' => 6,
                'psize' => 4,
                'opcode' => 1, // Query
                'senderEtherAddress' => $this->myMac,
                'senderProtoAddress' => $this->myIp,
                'targetEtherAddress' => '00:00:00:00:00:00',
                'targetProtoAddress' => $this->gwIp,
            ]),
        ]);
    }
}
