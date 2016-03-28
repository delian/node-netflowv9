/**
 * This version support only compiled code and works with streams API
 */

//require('debug').enable('NetFlowV9');
var debug = require('debug')('NetFlowV9');
var dgram = require('dgram');
var clone = require('clone');
var util = require('util');
var e = require('events').EventEmitter;
var Dequeue = require('dequeue');

var nft = require('./js/nf9/nftypes');
var nf1PktDecode = require('./js/nf1/nf1decode');
var nf5PktDecode = require('./js/nf5/nf5decode');
var nf7PktDecode = require('./js/nf7/nf7decode');
var nf9PktDecode = require('./js/nf9/nf9decode');
var nfInfoTemplates = require('./js/nf9/nfinfotempl');

function nfPktDecode(msg,rinfo) {
    var version = msg.readUInt16BE(0);
    switch (version) {
        case 1:
            return this.nf1PktDecode(msg,rinfo);
            break;
        case 5:
            return this.nf5PktDecode(msg,rinfo);
            break;
        case 7:
            return this.nf7PktDecode(msg,rinfo);
            break;
        case 9:
            return this.nf9PktDecode(msg,rinfo);
            break;
        default:
            debug('bad header version %d', version);
            return;
    }
}

function NetFlowV9(options) {
    if (!(this instanceof NetFlowV9)) return new NetFlowV9(options);
    var me = this;
    this.templates = {};
    this.nfTypes = clone(nft.nfTypes);
    this.nfScope = clone(nft.nfScope);
    this.cb = null;
    this.templateCb = null;
    this.socketType = 'udp4';
    this.port = null;
    this.proxy = null;
    this.fifo = new Dequeue();
    if (typeof options == 'function') this.cb = options; else
    if (typeof options.cb == 'function') this.cb = options.cb;
    if (typeof options.templateCb == 'function') this.templateCb = options.templateCb;
    if (typeof options == 'object') {
        if (options.ipv4num) decIpv4Rule[4] = "o['$name']=buf.readUInt32BE($pos);";
        if (options.nfTypes) this.nfTypes = util._extend(this.nfTypes,options.nfTypes); // Inherit nfTypes
        if (options.nfScope) this.nfScope = util._extend(this.nfScope,options.nfScope); // Inherit nfTypes
        if (options.socketType) this.socketType = options.socketType;
        if (options.port) this.port = options.port;
        if (options.templates) this.templates = options.templates;
        if (options.fwd) this.fwd = options.fwd;
        if (typeof options.proxy == 'object' ||
            typeof options.proxy == 'string') {
            this.proxy = [];
            if (typeof options.proxy == 'string') {
                debug('Defining proxy destination %s',options.proxy);
                var m = options.proxy.match(/^(.*)(\:(\d+))$/);
                if (m) {
                    this.proxy.push({host: m[1], port: m[3]||5555});
                    debug('Proxy added %s:%s',m[1],m[3]||5555);
                }
            } else {
                for (var k in options.proxy) {
                    var v = options.proxy[k];
                    if (typeof v == 'string') {
                        debug('Defining proxy destination %s = %s',k,v);
                        var m = v.match(/^(.*)(\:(\d+))$/);
                        if (m) {
                            this.proxy.push({host: m[1], port: m[3]||5555});
                            debug('Proxy added %s:%s',m[1],m[3]||5555);
                        }
                    }
                }
            }
            
            if (this.proxy.length == 0) this.proxy = null;
        }
        e.call(this,options);
    }

    this.server = dgram.createSocket(this.socketType);
    this.server.on('message',function(msg,rinfo){
        me.fifo.push([msg, rinfo]);
        if (!me.closed && me.set) {
            me.set = false;
            setImmediate(me.fetch);
        }
        if (me.proxy) { // Resend the traffic
            me.proxy.forEach(function(p) {
                me.server.send(msg,0,msg.length,p.port,p.host,function() {});
            });
        }
    });

    this.server.on('close', function() {
        this.closed = true;
    });

    this.listen = function(port,host,cb) {
        me.fetch();
        setTimeout(function() {
            if (host && typeof host === 'function')
              me.server.bind(port,host);
            else if (host && typeof host === 'string' && cb)
              me.server.bind(port,host,cb);
            else if (host && typeof host === 'string' && !cb)
              me.server.bind(port,host);
            else if (!host && cb)
              me.server.bind(port, cb);
            else
              me.server.bind(port);
        },50);
    };

    this.fetch = function() {
        while (me.fifo.length > 0 && !this.closed) {
            var data = me.fifo.shift();
            var msg = data[0];
            var rinfo = data[1];
            var startTime = new Date().getTime();
            if (me.fwd) {
                var data = JSON.parse(msg.toString());
                msg = new Buffer(data.buffer);
                rinfo = data.rinfo;
            }
            if (rinfo.size<20) return;
            var o = me.nfPktDecode(msg,rinfo);
            var timeMs = (new Date().getTime()) - startTime;
            if (o && o.flows.length > 0) { // If the packet does not contain flows, only templates we do not decode
                o.rinfo = rinfo;
                o.packet = msg;
                o.decodeMs = timeMs;
                if (me.cb)
                    me.cb(o);
                else
                    me.emit('data',o);
            } else if (o && o.templates) {
                o.rinfo = rinfo;
                o.packet = msg;
                o.decodeMs = timeMs;
                if (me.templateCb)
                    me.templateCb(o);
                else
                    me.emit('template', o);
            } else {
                debug('Undecoded flows',o);
            }
        }

        me.set = true;
    };

    if (this.port) this.listen(options.port, options.host);
}

util.inherits(NetFlowV9,e);
NetFlowV9.prototype.nfInfoTemplates = nfInfoTemplates;
NetFlowV9.prototype.nfPktDecode = nfPktDecode;
NetFlowV9.prototype.nf1PktDecode = nf1PktDecode;
NetFlowV9.prototype.nf5PktDecode = nf5PktDecode;
NetFlowV9.prototype.nf7PktDecode = nf7PktDecode;
NetFlowV9.prototype.nf9PktDecode = nf9PktDecode;
module.exports = NetFlowV9;
