<?php

declare(strict_types = 1);

if(!in_array('pcap', stream_get_wrappers())) {
    \stream_wrapper_register('pcap', 'RTCKit\\Pcap\\Stream\\FFI\\StreamWrapper');
}
