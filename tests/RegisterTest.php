<?php

declare(strict_types = 1);

namespace RTCKit\Pcap\Stream\FFI;

class RegisterTest extends \PHPUnit\Framework\TestCase {
    /** @test */
    public function shouldShowInStream_get_wrappers() {
        $this->assertContains('pcap', stream_get_wrappers());
    }
}
