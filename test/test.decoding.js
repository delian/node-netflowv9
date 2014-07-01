var expect = require('chai').expect;

var NetFlowV9 = require('../netflowv9');

var VYOS_PACKET = '000900070002549b53b289a200000001000000000000005c0400001500150004001600040001000400020004003c0001000a0002000e0002003d00010003000400080004000c000400070002000b00020005000100060001000400010038000600500006003a000200c90004003000010000005c0401001500150004001600040001000400020004003c0001000a0002000e0002003d00010003000400080004000c000400070002000b00020005000100060001000400010051000600390006003b000200c90004003000010000005c0800001500150004001600040001000400020004003c0001000a0002000e0002003d000100030004001b0010001c00100005000100070002000b000200060001000400010038000600500006003a000200c90004003000010000005c0801001500150004001600040001000400020004003c0001000a0002000e0002003d000100030004001b0010001c00100005000100070002000b000200060001000400010051000600390006003b000200c90004003000010001001a10000004000c000100040030000100310001003200041000000e000000000102000001f4040000400000209e0000209e0000002800000001040003000000000000000a640054c0004c0264aa0050001006001b2fb9484980ee7395562800000000000301';



describe('NetFlowV9', function () {

    it('should be a function', function (done) {
        expect(NetFlowV9).to.be.an('function'); //is actually a constructor
        done();
    });

    it('should have nfPktDecode', function (done) {
        expect(NetFlowV9).to.have.property('nfPktDecode');
        done();
    });

    describe('nfPktDecode', function () {
        it('should be able to decode vyos packet', function (done) {
            var buffer = new Buffer(VYOS_PACKET, 'hex');
            var templates = {};
            expect(buffer).to.have.length(VYOS_PACKET.length/2);
            var r = NetFlowV9.nfPktDecode(buffer, templates);
            expect(templates).to.have.property('1024');
            expect(templates).to.have.property('1025');
            expect(templates).to.have.property('2048');
            expect(templates).to.have.property('2049');
            expect(r).to.have.property('header');
            expect(r).to.have.property('flows');

            var header = r.header;
            expect(header).to.have.property('version', 9);
            expect(header).to.have.property('count', 7);
            expect(header).to.have.property('uptime', 152731);
            expect(header).to.have.property('seconds', 1404209570);
            expect(header).to.have.property('sequence', 1);
            expect(header).to.have.property('sourceId', 0);

            var flows = r.flows;
            expect(flows).to.have.length(1);
            
            var f1 = flows[0];
            expect(f1).to.have.property('ipv4_src_addr', '10.100.0.84');
            expect(f1).to.have.property('ipv4_dst_addr', '192.0.76.2');
            expect(f1).to.have.property('in_pkts', 1);
            //TODO:test everything
            done();
        });
    });

});