node-netflowv9
==============

NetFlow Version 1,5,7,9 library for Node.JS
NetFlow Version 10 (IPFix) is next (a lot of the IPFIX types are implemented already)!

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
      flow: [
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
         flow_sampler_id: 2 } } ]


There will be one callback for each packet, which may contain more than one flow.

Additionally, you can use the collector to listen for template updates:

    var collector = Collector({port: 3000});
    collector.on('data', function(data) {
        console.log(data);
    });
    collector.on('template', function(data) {
        console.log(data);
    });

You can also access a NetFlow decode function directly. Do something like this:

    var netflowPktDecoder = require('node-netflowv9').nfPktDecode;
    ....
    console.log(netflowPktDecoder(buffer))

Currently we support netflow version 1, 5, 7 and 9.

## Options

You can initialize the collector with either callback function only or a group of options within an object.

The following options are available during initialization:

**port** - defines the port where our collector will listen to.

    Collector({ port: 5000, cb: function (flow) { console.log(flow) } })

If no port is provided, then the underlying socket will not be initialized (bind to a port) until you call listen method with a port as a parameter:

    Collector(function (flow) { console.log(flow) }).listen(port)

**host** - binds to a particular host on the local interfaces.

    Collector({ port: 5000, host: '0.0.0.0', cb: function (flow) { console.log(flow) } })

**templates** - provides the default templates to be used for incoming traffic

    Collector({ port: 5000, templates: { '127.0.0.1:5323': { '235': { len: 344, ...

**cb** - defines a callback function to be executed for every flow. If no call back function is provided, then the collector fires 'data' event for each received flow

    Collector({ cb: function (flow) { console.log(flow) } }).listen(5000)

**templateCb** - defines a callback function to be executed for templates. If no call back function is provided, then the collector fires 'template' event for the received templates.

    Collector({ templateCb: function(data) { console.log(data) } }).listen(5000);

**ipv4num** - defines that we want to receive the IPv4 ip address as a number, instead of decoded in a readable dot format

    Collector({ ipv4num: true, cb: function (flow) { console.log(flow) } }).listen(5000)

**socketType** - defines to what socket type we will bind to. Default is udp4. You can change it to udp6 is you like.

    Collector({ socketType: 'udp6', cb: function (flow) { console.log(flow) } }).listen(5000)

**nfTypes** - defines your own decoders to NetFlow v9+ types

**nfScope** - defines your own decoders to NetFlow v9+ Option Template scopes

## Define your own decoders for NetFlow v9+ types

NetFlow v9 could be extended with vendor specific types and many vendors define their own. There could be no netflow collector in the world that decodes all the specific vendor types.
By default this library decodes in readable format all the types it recognises. All the unknown types are decoded as 'unknown_type_XXX' where XXX is the type ID. The data is provided as a HEX string.
But you can extend the library yourself. You can even replace how current types are decoded. You can even do that on fly (you can dynamically change how the type is decoded in different periods of time).

To understand how to do that, you have to learn a bit about the internals of how this module works.

* When a new flowset template is received from the NetFlow Agent, this netflow module generates and compile (with new Function()) a decoding function
* When a netflow is received for a known flowset template (we have a compiled function for it) - the function is simply executed

This approach is quite simple and provides enormous performance. The function code is as small as possible and as well on first execution Node.JS compiles it with JIT and the result is really fast.

The function code is generated with templates that contains the javascript code to be add for each netflow type, identified by its ID.

Each template consist of an object of the following form:

    { name: 'property-name', compileRule: compileRuleObject }

*compileRuleObject* contains rules how that netflow type to be decoded, depending on its length.
The reason for that is, that some of the netflow types are variable length. And you may have to execute different code to decode them depending on the length.
The *compileRuleObject* format is simple:

    {
       length: 'javascript code as a string that decode this value',
       ...
    }

There is a special length property of 0. This code will be used, if there is no more specific decode defined for a length. For example:

    {
       4: 'code used to decode this netflow type with length of 4',
       8: 'code used to decode this netflow type with length of 8',
       0: 'code used to decode ANY OTHER length'
    }

### decoding code

The decoding code must be a string that contains javascript code. This code will be concatenated to the function body before compilation. If that code contain errors or simply does not work as expected it could crash the collector. So be careful.

There are few variables you have to use:

**$pos** - this string is replaced with a number containing the current position of the netflow type within the binary buffer.

**$len** - this string is replaced with a number containing the length of the netflow type

**$name** - this string is replaced with a string containing the name property of the netflow type (defined by you above)

**buf** - is Node.JS Buffer object containing the Flow we want to decode

**o** - this is the object where the decoded flow is written to.

Everything else is pure javascript. It is good if you know the restrictions of the javascript and Node.JS capabilities of the Function() method, but not necessary to allow you to write simple decoding by yourself.

If you want to decode a string, of variable length, you could write a compileRuleObject of the form:

    {
       0: 'o["$name"] = buf.toString("utf8",$pos,$pos+$len)'
    }

The example above will say that for this netfow type, whatever length it has, we will decode the value as utf8 string.

### Example

Lets assume you want to write you own code for decoding a NetFlow type, lets say 4444, which could be of variable length, and contains a integer number.

You can write a code like this:

    Collector({
       port: 5000,
       nfTypes: {
          4444: {   // 4444 is the NetFlow Type ID which decoding we want to replace
             name: 'my_vendor_type4444', // This will be the property name, that will contain the decoded value, it will be also the value of the $name
             compileRule: {
                 1: "o['$name']=buf.readUInt8($pos);", // This is how we decode type of length 1 to a number
                 2: "o['$name']=buf.readUInt16BE($pos);", // This is how we decode type of length 2 to a number
                 3: "o['$name']=buf.readUInt8($pos)*65536+buf.readUInt16BE($pos+1);", // This is how we decode type of length 3 to a number
                 4: "o['$name']=buf.readUInt32BE($pos);", // This is how we decode type of length 4 to a number
                 5: "o['$name']=buf.readUInt8($pos)*4294967296+buf.readUInt32BE($pos+1);", // This is how we decode type of length 5 to a number
                 6: "o['$name']=buf.readUInt16BE($pos)*4294967296+buf.readUInt32BE($pos+2);", // This is how we decode type of length 6 to a number
                 8: "o['$name']=buf.readUInt32BE($pos)*4294967296+buf.readUInt32BE($pos+4);", // This is how we decode type of length 8 to a number
                 0: "o['$name']='Unsupported Length of $len';"
             }
          }
       },
       cb: function (flow) {
          console.log(flow)
       }
    });

It looks to be a bit complex, but actually it is not.
In most of the cases, you don't have to define a compile rule for each different length.
The following example defines a decoding for a netflow type 6789 that carry a string:

    var colObj = Collector(function (flow) {
          console.log(flow)
    });

    colObj.listen(5000);

    colObj.nfTypes[6789] = {
        name: 'vendor_string',
        compileRule: {
            0: 'o["$name"] = buf.toString("utf8",$pos,$pos+$len);' // Never forget the ; at the end!
        }
    }

As you can see, we can also change the decoding on fly, by defining a property for that netflow type within the nfTypes property of the colObj (the Collector object).
Next time when the NetFlow Agent send us a NetFlow Template definition containing this netflow type, the new rule will be used (the routers usually send temlpates from time to time, so even currently compiled templates are recompiled).

You could also overwrite the default property names where the decoded data is written. For example:


    var colObj = Collector(function (flow) {
          console.log(flow)
    });
    colObj.listen(5000);

    colObj.nfTypes[14].name = 'outputInterface';
    colObj.nfTypes[10].name = 'inputInterface';



## Logging / Debugging the module

You can use the debug module to turn on the logging, in order to debug how the library behave.
The following example show you how:

    require('debug').enable('NetFlowV9');
    var Collector = require('node-netflowv9');
    Collector(function(flow) {
        console.log(flow);
    }).listen(5555);

## Multiple collectors

The module allows you to define multiple collectors at the same time.
For example:

    var Collector = require('node-netflowv9');

    Collector(function(flow) { // Collector 1 listening on port 5555
        console.log(flow);
    }).listen(5555);

    Collector(function(flow) { // Collector 2 listening on port 6666
        console.log(flow);
    }).listen(6666);

## NetFlowV9 Options Template

NetFlowV9 support Options template, where there could be an option Flow Set that contains data for a predefined fields within a certain scope.
This module supports the Options Template and provides the output of it as it is any other flow. The only difference is that there is a property **isOption** set to true to remind to your code, that this data has come from an Option Template.

Currently the following nfScope are supported - system, interface, line_card, netflow_cache.
You can overwrite the decoding of them, or add another the same way (and using absolutley the same format) as you overwrite nfTypes.
