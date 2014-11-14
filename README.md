node-netflowv9
==============

NetFlow Version 1,5,7,9 library for Node.JS

The library is still under development, please be careful! It has been tested with Cisco IOS XR and IPv4 although it must work with IPv6 too! Please log problems in the issues section!

## Usage

The usage of the netflowv9 collector library is very very simple. You just have to do something like this:


    var Collector = require('node-netflowv9');
    
    Collector(function(flow) {
        console.log(flow);
    }).listen(3000);

or you can use it as event provider:

    Collector({port: 3000}).on('data',function(flow) {
        console.log(flow);
    });


The flow will be presented in a format very similar to this:


    { header: 
      { version: 9,
         count: 25,
         uptime: 2452864139,
         seconds: 1401951592,
         sequence: 254138992,
         sourceId: 2081 },
      rinfo: 
      { address: '15.21.21.13',
         family: 'IPv4',
         port: 29471,
         size: 1452 },
      packet: Buffer <00 00 00 00 ....>
      flow: 
      { in_pkts: 3,
         in_bytes: 144,
         ipv4_src_addr: '15.23.23.37',
         ipv4_dst_addr: '16.16.19.165',
         input_snmp: 27,
         output_snmp: 16,
         last_switched: 2452753808,
         first_switched: 2452744429,
         l4_src_port: 61538,
         l4_dst_port: 62348,
         out_as: 0,
         in_as: 0,
         bgp_ipv4_next_hop: '16.16.1.1',
         src_mask: 32,
         dst_mask: 24,
         protocol: 17,
         tcp_flags: 0,
         src_tos: 0,
         direction: 1,
         fw_status: 64,
         flow_sampler_id: 2 } }


There will be one callback for each packet, which may contain more than one flow.

You can also access a NetFlow decode function directly. Do something like this:

    var netflowPktDecoder = require('node-netflowv9').nf9PktDecode;
    ....
    console.log(netflowPktDecoder(buffer))

Currently we support netflow version 1, 5, 7 and 9.
