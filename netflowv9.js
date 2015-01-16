/**
 * Created by delian on 11/11/14.
 * New version of the NetFlow V9 code
 * This version support only compiled code and works with streams API
 */

//require('debug').enable('NetFlowV9');
var debug = require('debug')('NetFlowV9');
var dgram = require('dgram');
var util = require('util');
var e = require('events').EventEmitter;

var decNumRule = {
    1: "o['$name']=buf.readUInt8($pos);",
    2: "o['$name']=buf.readUInt16BE($pos);",
    3: "o['$name']=buf.readUInt8($pos)*65536+buf.readUInt16BE($pos+1);",
    4: "o['$name']=buf.readUInt32BE($pos);",
    5: "o['$name']=buf.readUInt8($pos)*4294967296+buf.readUInt32BE($pos+1);",
    6: "o['$name']=buf.readUInt16BE($pos)*4294967296+buf.readUInt32BE($pos+2);",
    8: "o['$name']=buf.readUInt32BE($pos)*4294967296+buf.readUInt32BE($pos+4);"
};

var decTimestamp = decNumRule;
var decTsMs = decTimestamp;
var decTsMcs = decTimestamp;
var decTsNs = decTimestamp;

var decIpv4Rule = {
    4: "o['$name']=(t=buf.readUInt32BE($pos),(parseInt(t/16777216)%256)+'.'+(parseInt(t/65536)%256)+'.'+(parseInt(t/256)%256)+'.'+(t%256));"
};

var decIpv6Rule = {
    16: "o['$name']=buf.toString('hex',$pos,$pos+$len);"
};

var decMacRule = {
    0: "o['$name']=buf.toString('hex',$pos,$pos+$len);"
};

var decStringRule = {
    0: 'o[\'$name\']=buf.toString(\'utf8\',$pos,$pos+$len).replace(/\\0/g,\'\');'
};

var nfTypes = {
    1: {name: 'in_bytes', compileRule: decNumRule},
    2: {name: 'in_pkts', compileRule: decNumRule},
    3: {name: 'flows', compileRule: decNumRule},
    4: {name: 'protocol', compileRule: decNumRule},
    5: {name: 'src_tos', compileRule: decNumRule},
    6: {name: 'tcp_flags', compileRule: decNumRule},
    7: {name: 'l4_src_port', compileRule: decNumRule},
    8: {name: 'ipv4_src_addr', compileRule: decIpv4Rule},
    9: {name: 'src_mask', compileRule: decNumRule},
    10: {name: 'input_snmp', compileRule: decNumRule},
    11: {name: 'l4_dst_port', compileRule: decNumRule},
    12: {name: 'ipv4_dst_addr', compileRule: decIpv4Rule},
    13: {name: 'dst_mask', compileRule: decNumRule},
    14: {name: 'output_snmp', compileRule: decNumRule},
    15: {name: 'ipv4_next_hop', compileRule: decIpv4Rule},
    16: {name: 'src_as', compileRule: decNumRule},
    17: {name: 'dst_as', compileRule: decNumRule},
    18: {name: 'bgp_ipv4_next_hop', compileRule: decIpv4Rule},
    19: {name: 'mul_dst_pkts', compileRule: decNumRule},
    20: {name: 'mul_dst_bytes', compileRule: decNumRule},
    21: {name: 'last_switched', compileRule: decNumRule},
    22: {name: 'first_switched', compileRule: decNumRule},
    23: {name: 'out_bytes', compileRule: decNumRule},
    24: {name: 'out_pkts', compileRule: decNumRule},
    25: {name: 'min_pkt_lngth', compileRule: decNumRule},
    26: {name: 'max_pkt_lngth', compileRule: decNumRule},
    27: {name: 'ipv6_src_addr', compileRule: decIpv6Rule},
    28: {name: 'ipv6_dst_addr', compileRule: decIpv6Rule},
    29: {name: 'ipv6_src_mask', compileRule: decNumRule},
    30: {name: 'ipv6_dst_mask', compileRule: decNumRule},
    31: {name: 'ipv6_flow_label', compileRule: decNumRule},
    32: {name: 'icmp_type', compileRule: decNumRule},
    33: {name: 'mul_igmp_type', compileRule: decNumRule},
    34: {name: 'sampling_interval', compileRule: decNumRule},
    35: {name: 'sampling_algorithm', compileRule: decNumRule},
    36: {name: 'flow_active_timeout', compileRule: decNumRule},
    37: {name: 'flow_inactive_timeout', compileRule: decNumRule},
    38: {name: 'engine_type', compileRule: decNumRule},
    39: {name: 'engine_id', compileRule: decNumRule},
    40: {name: 'total_bytes_exp', compileRule: decNumRule},
    41: {name: 'total_pkts_exp', compileRule: decNumRule},
    42: {name: 'total_flows_exp', compileRule: decNumRule},
    44: {name: 'ipv4_src_prefix', compileRule: decIpv4Rule},
    45: {name: 'ipv4_dst_prefix', compileRule: decIpv4Rule},
    46: {name: 'mpls_top_label_type', compileRule: decIpv4Rule},
    47: {name: 'mpls_top_label_ip_addr', compileRule: decIpv4Rule},
    48: {name: 'flow_sampler_id', compileRule: decNumRule},
    49: {name: 'flow_sampler_mode', compileRule: decNumRule},
    50: {name: 'flow_sampler_random_interval', compileRule: decNumRule},
    52: {name: 'min_ttl', compileRule: decNumRule},
    53: {name: 'max_ttl', compileRule: decNumRule},
    54: {name: 'ipv4_ident', compileRule: decNumRule},
    55: {name: 'dst_tos', compileRule: decNumRule},
    56: {name: 'in_src_mac', compileRule: decMacRule},
    57: {name: 'out_dst_mac', compileRule: decMacRule},
    58: {name: 'src_vlan', compileRule: decNumRule},
    59: {name: 'dst_vlan', compileRule: decNumRule},
    60: {name: 'ip_protocol_version', compileRule: decNumRule},
    61: {name: 'direction', compileRule: decNumRule},
    62: {name: 'ipv6_next_hop', compileRule: decIpv6Rule},
    63: {name: 'bpg_ipv6_next_hop', compileRule: decIpv6Rule},
    64: {name: 'ipv6_option_headers', compileRule: decNumRule},
    70: {name: 'mpls_label_1', compileRule: decNumRule},
    71: {name: 'mpls_label_2', compileRule: decNumRule},
    72: {name: 'mpls_label_3', compileRule: decNumRule},
    73: {name: 'mpls_label_4', compileRule: decNumRule},
    74: {name: 'mpls_label_5', compileRule: decNumRule},
    75: {name: 'mpls_label_6', compileRule: decNumRule},
    76: {name: 'mpls_label_7', compileRule: decNumRule},
    77: {name: 'mpls_label_8', compileRule: decNumRule},
    78: {name: 'mpls_label_9', compileRule: decNumRule},
    79: {name: 'mpls_label_10', compileRule: decNumRule},
    80: {name: 'in_dst_mac', compileRule: decMacRule},
    81: {name: 'out_src_mac', compileRule: decMacRule},
    82: {name: 'if_name', compileRule: decStringRule},
    83: {name: 'if_desc', compileRule: decStringRule},
    84: {name: 'sampler_name', compileRule: decStringRule},
    85: {name: 'in_permanent_bytes', compileRule: decNumRule},
    86: {name: 'in_permanent_pkts', compileRule: decNumRule},
    87: {name: 'flagsAndSamplerId', compileRule: decNumRule}, // Deprecated
    88: {name: 'fragment_offset', compileRule: decNumRule},
    89: {name: 'fw_status', compileRule: decNumRule},
    90: {name: 'mpls_pal_rd', compileRule: decNumRule},
    91: {name: 'mpls_prefix_len', compileRule: decNumRule},
    92: {name: 'src_traffic_index', compileRule: decNumRule},
    93: {name: 'dst_traffic_index', compileRule: decNumRule},
    94: {name: 'application_descr', compileRule: decStringRule},
    95: {name: 'application_tag', compileRule: decMacRule},
    96: {name: 'application_name', compileRule: decStringRule},
    98: {name: 'postIpDiffServCodePoint', compileRule: decNumRule},
    99: {name: 'replication_factor', compileRule: decNumRule},
    100: {name: 'className', compileRule: decStringRule},
    101: {name: 'classificationEngineId', compileRule: decNumRule},
    102: {name: 'layer2packetSectionOffset', compileRule: decNumRule}, // Deprecated
    103: {name: 'layer2packetSectionSize', compileRule: decNumRule}, // Deprecated
    104: {name: 'layer2packetSectionData', compileRule: decMacRule},
    //above 127 is in ipfix
    128: {name: 'in_as', compileRule: decNumRule},
    129: {name: 'out_as', compileRule: decNumRule},
    130: {name: 'exporterIPv4Address', compileRule: decIpv4Rule},
    131: {name: 'exporterIPv6Address', compileRule: decIpv6Rule},
    132: {name: 'droppedOctetDeltaCount', compileRule: decNumRule},
    133: {name: 'droppedPacketDeltaCount', compileRule: decNumRule},
    134: {name: 'droppedOctetTotalCount', compileRule: decNumRule},
    135: {name: 'droppedPacketTotalCount', compileRule: decNumRule},
    136: {name: 'flowEndReason', compileRule: decNumRule},
    137: {name: 'commonPropertiesId', compileRule: decNumRule},
    138: {name: 'observationPointId', compileRule: decNumRule},
    139: {name: 'icmpTypeCodeIPv6', compileRule: decNumRule},
    140: {name: 'mplsTopLabelIPv6Address', compileRule: decIpv6Rule},
    141: {name: 'lineCardId', compileRule: decNumRule},
    142: {name: 'portId', compileRule: decNumRule},
    143: {name: 'meteringProcessId', compileRule: decNumRule},
    144: {name: 'exportingProcessId', compileRule: decNumRule},
    145: {name: 'templateId', compileRule: decNumRule},
    146: {name: 'wlanChannelId', compileRule: decNumRule},
    147: {name: 'wlanSSID', compileRule: decStringRule},
    148: {name: 'flowId', compileRule: decNumRule},
    149: {name: 'observationDomainId', compileRule: decNumRule},
    150: {name: 'flowStartSeconds', compileRule: decTimestamp},
    151: {name: 'flowEndSeconds', compileRule: decTimestamp},
    152: {name: 'flowStartMilliseconds', compileRule: decTsMs},
    153: {name: 'flowEndMilliseconds', compileRule: decTsMs},
    154: {name: 'flowStartMicroseconds', compileRule: decTsMcs},
    155: {name: 'flowEndMicroseconds', compileRule: decTsMcs},
    156: {name: 'flowStartNanoseconds', compileRule: decTsNs},
    157: {name: 'flowEndNanoseconds', compileRule: decTsNs},
    158: {name: 'flowStartDeltaMicroseconds', compileRule: decNumRule},
    159: {name: 'flowEndDeltaMicroseconds', compileRule: decNumRule},
    160: {name: 'systemInitTimeMilliseconds', compileRule: decTsMs},
    161: {name: 'flowDurationMilliseconds', compileRule: decNumRule},
    162: {name: 'flowDurationMicroseconds', compileRule: decNumRule},
    163: {name: 'observedFlowTotalCount', compileRule: decNumRule},
    164: {name: 'ignoredPacketTotalCount', compileRule: decNumRule},
    165: {name: 'ignoredOctetTotalCount', compileRule: decNumRule},
    166: {name: 'notSentFlowTotalCount', compileRule: decNumRule},
    167: {name: 'notSentPacketTotalCount', compileRule: decNumRule},
    168: {name: 'notSentOctetTotalCount', compileRule: decNumRule},
    169: {name: 'destinationIPv6Prefix', compileRule: decIpv6Rule},
    170: {name: 'sourceIPv6Prefix', compileRule: decIpv6Rule},
    171: {name: 'postOctetTotalCount', compileRule: decNumRule},
    172: {name: 'postPacketTotalCount', compileRule: decNumRule},
    173: {name: 'flowKeyIndicator', compileRule: decNumRule},
    174: {name: 'postMCastPacketTotalCount', compileRule: decNumRule},
    175: {name: 'postMCastOctetTotalCount', compileRule: decNumRule},
    176: {name: 'icmpTypeIPv4', compileRule: decNumRule},
    177: {name: 'icmpCodeIPv4', compileRule: decNumRule},
    178: {name: 'icmpTypeIPv6', compileRule: decNumRule},
    179: {name: 'icmpCodeIPv6', compileRule: decNumRule},
    180: {name: 'udpSourcePort', compileRule: decNumRule},
    181: {name: 'udpDestinationPort', compileRule: decNumRule},
    182: {name: 'tcpSourcePort', compileRule: decNumRule},
    183: {name: 'tcpDestinationPort', compileRule: decNumRule},
    184: {name: 'tcpSequenceNumber', compileRule: decNumRule},
    185: {name: 'tcpAcknowledgementNumber', compileRule: decNumRule},
    186: {name: 'tcpWindowSize', compileRule: decNumRule},
    187: {name: 'tcpUrgentPointer', compileRule: decNumRule},
    188: {name: 'tcpHeaderLength', compileRule: decNumRule},
    189: {name: 'ipHeaderLength', compileRule: decNumRule},
    190: {name: 'totalLengthIPv4', compileRule: decNumRule},
    191: {name: 'payloadLengthIPv6', compileRule: decNumRule},
    192: {name: 'ipTTL', compileRule: decNumRule},
    193: {name: 'nextHeaderIPv6', compileRule: decNumRule},
    194: {name: 'mplsPayloadLength', compileRule: decNumRule},
    195: {name: 'ipDiffServCodePoint', compileRule: decNumRule},
    //the following are taken from from http://www.iana.org/assignments/ipfix/ipfix.xhtml
    196: {name: 'ipPrecedence', compileRule: decNumRule},
    197: {name: 'fragmentFlags', compileRule: decNumRule},
    198: {name: 'octetDeltaSumOfSquares', compileRule: decNumRule},
    199: {name: 'octetTotalSumOfSquares', compileRule: decNumRule},
    200: {name: 'mplsTopLabelTTL', compileRule: decNumRule},
    201: {name: 'mplsLabelStackLength', compileRule: decNumRule},
    202: {name: 'mplsLabelStackDepth', compileRule: decNumRule},
    203: {name: 'mplsTopLabelExp', compileRule: decNumRule},
    204: {name: 'ipPayloadLength', compileRule: decNumRule},
    205: {name: 'udpMessageLength', compileRule: decNumRule},
    206: {name: 'isMulticast', compileRule: decNumRule},
    207: {name: 'ipv4IHL', compileRule: decNumRule},
    208: {name: 'ipv4Options', compileRule: decNumRule},
    209: {name: 'tcpOptions', compileRule: decNumRule},
    210: {name: 'paddingOctets', compileRule: decMacRule},
    211: {name: 'collectorIPv4Address', compileRule: decIpv4Rule},
    212: {name: 'collectorIPv6Address', compileRule: decIpv6Rule},
    213: {name: 'exportInterface', compileRule: decNumRule},
    214: {name: 'exportProtocolVersion', compileRule: decNumRule},
    215: {name: 'exportTransportProtocol', compileRule: decNumRule},
    216: {name: 'collectorTransportPort', compileRule: decNumRule},
    217: {name: 'exporterTransportPort', compileRule: decNumRule},
    218: {name: 'tcpSynTotalCount', compileRule: decNumRule},
    219: {name: 'tcpFinTotalCount', compileRule: decNumRule},
    220: {name: 'tcpRstTotalCount', compileRule: decNumRule},
    221: {name: 'tcpPshTotalCount', compileRule: decNumRule},
    222: {name: 'tcpAckTotalCount', compileRule: decNumRule},
    223: {name: 'tcpUrgTotalCount', compileRule: decNumRule},
    224: {name: 'ipTotalLength', compileRule: decNumRule},
    225: {name: 'postNATSourceIPv4Address', compileRule: decIpv4Rule},
    226: {name: 'postNATDestinationIPv4Address', compileRule: decIpv4Rule},
    227: {name: 'postNAPTSourceTransportPort', compileRule: decNumRule},
    228: {name: 'postNAPTDestinationTransportPort', compileRule: decNumRule},
    229: {name: 'natOriginatingAddressRealm', compileRule: decNumRule},
    230: {name: 'natEvent', compileRule: decNumRule},
    231: {name: 'initiatorOctets', compileRule: decNumRule},
    232: {name: 'responderOctets', compileRule: decNumRule},
    233: {name: 'firewallEvent', compileRule: decNumRule},
    234: {name: 'ingressVRFID', compileRule: decNumRule},
    235: {name: 'egressVRFID', compileRule: decNumRule},
    236: {name: 'VRFname', compileRule: decStringRule},
    237: {name: 'postMplsTopLabelExp', compileRule: decNumRule},
    238: {name: 'tcpWindowScale', compileRule: decNumRule},
    239: {name: 'biflow_direction', compileRule: decNumRule},
    240: {name: 'ethernetHeaderLength', compileRule: decNumRule},
    241: {name: 'ethernetPayloadLength', compileRule: decNumRule},
    242: {name: 'ethernetTotalLength', compileRule: decNumRule},
    243: {name: 'dot1qVlanId', compileRule: decNumRule},
    244: {name: 'dot1qPriority', compileRule: decNumRule},
    245: {name: 'dot1qCustomerVlanId', compileRule: decNumRule},
    246: {name: 'dot1qCustomerPriority', compileRule: decNumRule},
    247: {name: 'metroEvcId', compileRule: decStringRule},
    248: {name: 'metroEvcType', compileRule: decNumRule},
    249: {name: 'pseudoWireId', compileRule: decNumRule},
    250: {name: 'pseudoWireType', compileRule: decNumRule},
    251: {name: 'pseudoWireControlWord', compileRule: decNumRule},
    252: {name: 'ingressPhysicalInterface', compileRule: decNumRule},
    253: {name: 'egressPhysicalInterface', compileRule: decNumRule},
    254: {name: 'postDot1qVlanId', compileRule: decNumRule},
    255: {name: 'postDot1qCustomerVlanId', compileRule: decNumRule},
    256: {name: 'ethernetType', compileRule: decNumRule},
    257: {name: 'postIpPrecedence', compileRule: decNumRule},
    258: {name: 'collectionTimeMilliseconds', compileRule: decTsMs},
    259: {name: 'exportSctpStreamId', compileRule: decNumRule},
    260: {name: 'maxExportSeconds', compileRule: decTimestamp},
    261: {name: 'maxFlowEndSeconds', compileRule: decTimestamp},
    262: {name: 'messageMD5Checksum', compileRule: decMacRule},
    263: {name: 'messageScope', compileRule: decNumRule},
    264: {name: 'minExportSeconds', compileRule: decTimestamp},
    265: {name: 'minFlowStartSeconds', compileRule: decTimestamp},
    266: {name: 'opaqueOctets', compileRule: decMacRule},
    267: {name: 'sessionScope', compileRule: decNumRule},
    268: {name: 'maxFlowEndMicroseconds', compileRule: decTsMcs},
    269: {name: 'maxFlowEndMilliseconds', compileRule: decTsMs},
    270: {name: 'maxFlowEndNanoseconds', compileRule: decTsNs},
    271: {name: 'minFlowStartMicroseconds', compileRule: decTsMcs},
    272: {name: 'minFlowStartMilliseconds', compileRule: decTsMs},
    273: {name: 'minFlowStartNanoseconds', compileRule: decTsNs},
    274: {name: 'collectorCertificate', compileRule: decMacRule},
    275: {name: 'exporterCertificate', compileRule: decMacRule},
    276: {name: 'dataRecordsReliability', compileRule: decNumRule},
    277: {name: 'observationPointType', compileRule: decNumRule},
    278: {name: 'connectionCountNew', compileRule: decNumRule},
    279: {name: 'connectionSumDuration', compileRule: decNumRule},
    280: {name: 'conn_tx_id',compileRule: decNumRule},
    //
    281: {name: 'postNATSourceIPv6Address',compileRule: decIpv6Rule},
    282: {name: 'postNATDestinationIPv6Address',compileRule: decIpv6Rule},
    283: {name: 'natPoolId',compileRule: decNumRule},
    284: {name: 'natPoolName',compileRule: decStringRule},
    285: {name: 'anonymizationFlags',compileRule: decNumRule},
    286: {name: 'anonymizationTechnique',compileRule: decNumRule},
    287: {name: 'informationElementIndex',compileRule: decNumRule},
    288: {name: 'p2pTechnology',compileRule: decStringRule},
    289: {name: 'tunnelTechnology',compileRule: decStringRule},
    290: {name: 'encryptedTechnology',compileRule: decStringRule},
    // 291: {name: 'basicList',compileRule: decNumRule},  // List type, not yet supported
    // 292: {name: 'subTemplateList',compileRule: decNumRule},
    // 293: {name: 'subTemplateMultiList',compileRule: decNumRule},
    294: {name: 'bgpValidityState',compileRule: decNumRule},
    295: {name: 'IPSecSPI',compileRule: decNumRule},
    296: {name: 'greKey',compileRule: decNumRule},
    297: {name: 'natType',compileRule: decNumRule},
    298: {name: 'initiatorPackets',compileRule: decNumRule},
    299: {name: 'responderPackets',compileRule: decNumRule},
    300: {name: 'observationDomainName',compileRule: decStringRule},
    301: {name: 'selectionSequenceId',compileRule: decNumRule},
    302: {name: 'selectorId',compileRule: decNumRule},
    303: {name: 'informationElementId',compileRule: decNumRule},
    304: {name: 'selectorAlgorithm',compileRule: decNumRule},
    305: {name: 'samplingPacketInterval',compileRule: decNumRule},
    306: {name: 'samplingPacketSpace',compileRule: decNumRule},
    307: {name: 'samplingTimeInterval',compileRule: decNumRule},
    308: {name: 'samplingTimeSpace',compileRule: decNumRule},
    309: {name: 'samplingSize',compileRule: decNumRule},
    310: {name: 'samplingPopulation',compileRule: decNumRule},
    // 311: {name: 'samplingProbability',compileRule: decNumRule}, // Float type has to be introduced
    312: {name: 'dataLinkFrameSize',compileRule: decNumRule},
    313: {name: 'ipHeaderPacketSection',compileRule: decMacRule},
    314: {name: 'ipPayloadPacketSection',compileRule: decMacRule},
    315: {name: 'dataLinkFrameSection',compileRule: decMacRule},
    316: {name: 'mplsLabelStackSection',compileRule: decMacRule},
    317: {name: 'mplsPayloadPacketSection',compileRule: decMacRule},
    318: {name: 'selectorIdTotalPktsObserved',compileRule: decNumRule},
    319: {name: 'selectorIdTotalPktsSelected',compileRule: decNumRule},
    // 320: {name: 'absoluteError',compileRule: decNumRule}, // Float type
    // 321: {name: 'relativeError',compileRule: decNumRule}, // Float type
    322: {name: 'observationTimeSeconds',compileRule: decTimestamp},
    323: {name: 'observationTimeMilliseconds',compileRule: decTsMs},
    324: {name: 'observationTimeMicroseconds',compileRule: decTsMcs},
    325: {name: 'observationTimeNanoseconds',compileRule: decTsNs},
    326: {name: 'digestHashValue',compileRule: decNumRule},
    327: {name: 'hashIPPayloadOffset',compileRule: decNumRule},
    328: {name: 'hashIPPayloadSize',compileRule: decNumRule},
    329: {name: 'hashOutputRangeMin',compileRule: decNumRule},
    330: {name: 'hashOutputRangeMax',compileRule: decNumRule},
    331: {name: 'hashSelectedRangeMin',compileRule: decNumRule},
    332: {name: 'hashSelectedRangeMax',compileRule: decNumRule},
    333: {name: 'hashDigestOutput',compileRule: decNumRule},
    334: {name: 'hashInitialiserValue',compileRule: decNumRule},
    335: {name: 'selectorName',compileRule: decStringRule},
    // 336: {name: 'upperCILimit',compileRule: decNumRule}, // Float type
    // 337: {name: 'lowerCILimit',compileRule: decNumRule}, // Float
    // 338: {name: 'confidenceLevel',compileRule: decNumRule}, // Float
    339: {name: 'informationElementDataType',compileRule: decNumRule},
    340: {name: 'informationElementDescription',compileRule: decStringRule},
    341: {name: 'informationElementName',compileRule: decStringRule},
    342: {name: 'informationElementRangeBegin',compileRule: decNumRule},
    343: {name: 'informationElementRangeEnd',compileRule: decNumRule},
    344: {name: 'informationElementSemantics',compileRule: decNumRule},
    345: {name: 'informationElementUnits',compileRule: decNumRule},
    346: {name: 'privateEnterpriseNumber',compileRule: decNumRule},
    347: {name: 'virtualStationInterfaceId',compileRule: decMacRule},
    348: {name: 'virtualStationInterfaceName',compileRule: decStringRule},
    349: {name: 'virtualStationUUID',compileRule: decMacRule},
    350: {name: 'virtualStationName',compileRule: decStringRule},
    351: {name: 'layer2SegmentId',compileRule: decNumRule},
    352: {name: 'layer2OctetDeltaCount',compileRule: decNumRule},
    353: {name: 'layer2OctetTotalCount',compileRule: decNumRule},
    354: {name: 'ingressUnicastPacketTotalCount',compileRule: decNumRule},
    355: {name: 'ingressMulticastPacketTotalCount',compileRule: decNumRule},
    356: {name: 'ingressBroadcastPacketTotalCount',compileRule: decNumRule},
    357: {name: 'egressUnicastPacketTotalCount',compileRule: decNumRule},
    358: {name: 'egressBroadcastPacketTotalCount',compileRule: decNumRule},
    359: {name: 'monitoringIntervalStartMilliSeconds',compileRule: decTsMs},
    360: {name: 'monitoringIntervalEndMilliSeconds',compileRule: decTsMs},
    361: {name: 'portRangeStart',compileRule: decNumRule},
    362: {name: 'portRangeEnd',compileRule: decNumRule},
    363: {name: 'portRangeStepSize',compileRule: decNumRule},
    364: {name: 'portRangeNumPorts',compileRule: decNumRule},
    365: {name: 'staMacAddress',compileRule: decMacRule},
    366: {name: 'staIPv4Address',compileRule: decIpv4Rule},
    367: {name: 'wtpMacAddress',compileRule: decMacRule},
    368: {name: 'ingressInterfaceType',compileRule: decNumRule},
    369: {name: 'egressInterfaceType',compileRule: decNumRule},
    370: {name: 'rtpSequenceNumber',compileRule: decNumRule},
    371: {name: 'userName',compileRule: decStringRule},
    372: {name: 'applicationCategoryName',compileRule: decStringRule},
    373: {name: 'applicationSubCategoryName',compileRule: decStringRule},
    374: {name: 'applicationGroupName',compileRule: decStringRule},
    375: {name: 'originalFlowsPresent',compileRule: decNumRule},
    376: {name: 'originalFlowsInitiated',compileRule: decNumRule},
    377: {name: 'originalFlowsCompleted',compileRule: decNumRule},
    378: {name: 'distinctCountOfSourceIPAddress',compileRule: decNumRule},
    379: {name: 'distinctCountOfDestinationIPAddress',compileRule: decNumRule},
    380: {name: 'distinctCountOfSourceIPv4Address',compileRule: decNumRule},
    381: {name: 'distinctCountOfDestinationIPv4Address',compileRule: decNumRule},
    382: {name: 'distinctCountOfSourceIPv6Address',compileRule: decNumRule},
    383: {name: 'distinctCountOfDestinationIPv6Address',compileRule: decNumRule},
    384: {name: 'valueDistributionMethod',compileRule: decNumRule},
    385: {name: 'rfc3550JitterMilliseconds',compileRule: decNumRule},
    386: {name: 'rfc3550JitterMicroseconds',compileRule: decNumRule},
    387: {name: 'rfc3550JitterNanoseconds',compileRule: decNumRule},
    388: {name: 'dot1qDEI',compileRule: decNumRule},
    389: {name: 'dot1qCustomerDEI',compileRule: decNumRule},
    390: {name: 'flowSelectorAlgorithm',compileRule: decNumRule},
    391: {name: 'flowSelectedOctetDeltaCount',compileRule: decNumRule},
    392: {name: 'flowSelectedPacketDeltaCount',compileRule: decNumRule},
    393: {name: 'flowSelectedFlowDeltaCount',compileRule: decNumRule},
    394: {name: 'selectorIDTotalFlowsObserved',compileRule: decNumRule},
    395: {name: 'selectorIDTotalFlowsSelected',compileRule: decNumRule},
    396: {name: 'samplingFlowInterval',compileRule: decNumRule},
    397: {name: 'samplingFlowSpacing',compileRule: decNumRule},
    398: {name: 'flowSamplingTimeInterval',compileRule: decNumRule},
    399: {name: 'flowSamplingTimeSpacing',compileRule: decNumRule},
    400: {name: 'hashFlowDomain',compileRule: decNumRule},
    401: {name: 'transportOctetDeltaCount',compileRule: decNumRule},
    402: {name: 'transportPacketDeltaCount',compileRule: decNumRule},
    403: {name: 'originalExporterIPv4Address',compileRule: decIpv4Rule},
    404: {name: 'originalExporterIPv6Address',compileRule: decIpv6Rule},
    405: {name: 'originalObservationDomainId',compileRule: decNumRule},
    406: {name: 'intermediateProcessId',compileRule: decNumRule},
    407: {name: 'ignoredDataRecordTotalCount',compileRule: decNumRule},
    408: {name: 'dataLinkFrameType',compileRule: decNumRule},
    409: {name: 'sectionOffset',compileRule: decNumRule},
    410: {name: 'sectionExportedOctets',compileRule: decNumRule},
    411: {name: 'dot1qServiceInstanceTag',compileRule: decMacRule},
    412: {name: 'dot1qServiceInstanceId',compileRule: decNumRule},
    413: {name: 'dot1qServiceInstancePriority',compileRule: decNumRule},
    414: {name: 'dot1qCustomerSourceMacAddress',compileRule: decMacRule},
    415: {name: 'dot1qCustomerDestinationMacAddress',compileRule: decMacRule},
    417: {name: 'postLayer2OctetDeltaCount',compileRule: decNumRule},
    418: {name: 'postMCastLayer2OctetDeltaCount',compileRule: decNumRule},
    420: {name: 'postLayer2OctetTotalCount',compileRule: decNumRule},
    421: {name: 'postMCastLayer2OctetTotalCount',compileRule: decNumRule},
    422: {name: 'minimumLayer2TotalLength',compileRule: decNumRule},
    423: {name: 'maximumLayer2TotalLength',compileRule: decNumRule},
    424: {name: 'droppedLayer2OctetDeltaCount',compileRule: decNumRule},
    425: {name: 'droppedLayer2OctetTotalCount',compileRule: decNumRule},
    426: {name: 'ignoredLayer2OctetTotalCount',compileRule: decNumRule},
    427: {name: 'notSentLayer2OctetTotalCount',compileRule: decNumRule},
    428: {name: 'layer2OctetDeltaSumOfSquares',compileRule: decNumRule},
    429: {name: 'layer2OctetTotalSumOfSquares',compileRule: decNumRule},
    430: {name: 'layer2FrameDeltaCount',compileRule: decNumRule},
    431: {name: 'layer2FrameTotalCount',compileRule: decNumRule},
    432: {name: 'pseudoWireDestinationIPv4Address',compileRule: decIpv4Rule},
    433: {name: 'ignoredLayer2FrameTotalCount',compileRule: decNumRule}
};

var nfScope = {
    1: { name: 'scope_system', compileRule: decMacRule },
    2: { name: 'scope_interface', compileRule: decStringRule },
    3: { name: 'scope_linecard', compileRule: decNumRule },
    4: { name: 'scope_netflow_cache', compileRule: decNumRule },
    5: { name: 'scope_template', compileRule: decStringRule }
};

function nf9PktDecode(msg) {
    var templates = this.templates || {};
    var nfTypes = this.nfTypes || {};

    var out = { header: {
        version: msg.readUInt16BE(0),
        count: msg.readUInt16BE(2),
        uptime: msg.readUInt32BE(4),
        seconds: msg.readUInt32BE(8),
        sequence: msg.readUInt32BE(12),
        sourceId: msg.readUInt32BE(16)
    }, flows: [] };

    function compileStatement(type, pos, len) {
        var nf = nfTypes[type];
        var cr = null;
        if (nf && nf.compileRule) {
            cr = nf.compileRule[len] || nf.compileRule[0];
            if (cr) {
                return cr.toString().replace(/(\$pos)/g, function (n) {
                    return pos
                }).replace(/(\$len)/g, function (n) {
                    return len
                }).replace(/(\$name)/g, function (n) {
                    return nf.name
                });
            }
        }
        debug('Unknown compile rule TYPE: %d POS: %d LEN: %d',type,pos,len);
        return "";
    }

    function compileTemplate(list) {
        var i, z, nf, n;
        var f = "var o = {}; var t;\n";
        for (i = 0, n = 0; i < list.length; i++, n += z.len) {
            z = list[i];
            nf = nfTypes[z.type];
            if (!nf) {
                debug('Unknown NF type %d', z.type);
                nf = nfTypes[z.type] = {
                    name: 'unknown_type_'+ z.type,
                    compileRule: decMacRule
                };
            }
            f += compileStatement(z.type, n, z.len) + ";\n";
        }
        f += "return o;\n";
        debug('The template will be compiled to %s',f);
        return new Function('buf', 'nfTypes', f);
    }

    function readTemplate(buffer) {
        // var fsId = buffer.readUInt16BE(0);
        var len = buffer.readUInt16BE(2);
        var buf = buffer.slice(4, len);
        while (buf.length > 0) {
            var tId = buf.readUInt16BE(0);
            var cnt = buf.readUInt16BE(2);
            var list = [];
            var len = 0;
            for (var i = 0; i < cnt; i++) {
                list.push({type: buf.readUInt16BE(4 + 4 * i), len: buf.readUInt16BE(6 + 4 * i)});
                len += buf.readUInt16BE(6 + 4 * i);
            }
            debug('compile template %s', tId);
            templates[tId] = {len: len, list: list, compiled: compileTemplate(list)};
            buf = buf.slice(4 + cnt * 4);
        }
    }

    function decodeTemplate(fsId, buf) {
        var o = templates[fsId].compiled(buf, nfTypes);
        o.fsId = fsId;
        return o;
    }

    function compileScope(type,pos,len) {
        var nf = nfScope[type];
        var cr = null;
        if (nf && nf.compileRule) {
            cr = nf.compileRule[len] || nf.compileRule[0];
            if (cr) {
                return cr.toString().replace(/(\$pos)/g, function (n) {
                    return pos
                }).replace(/(\$len)/g, function (n) {
                    return len
                }).replace(/(\$name)/g, function (n) {
                    return nf.name
                });
            }
        }
        debug('Unknown compile scope rule TYPE: %d POS: %d LEN: %d',type,pos,len);
        return "";
    }

    function readOptions(buffer) {
        var len = buffer.readUInt16BE(2);
        var tId = buffer.readUInt16BE(4);
        var osLen = buffer.readUInt16BE(6);
        var oLen = buffer.readUInt16BE(8);
        var buff = buffer.slice(10,len);
        debug('readOptions: len:%d tId:%d osLen:%d oLen:%d',len,tId,osLen,oLen,buff);
        var plen = 0;
        var cr = "var o={ isOption: true }; var t;\n";
        var type; var tlen;

        // Read the SCOPE
        var buf = buff.slice(0,osLen);
        while (buf.length > 3) {
            type = buf.readUInt16BE(0);
            tlen = buf.readUInt16BE(2);
            debug('    SCOPE type: %d (%s) len: %d, plen: %d', type,nfTypes[type].name,tlen,plen);
            if (type>0) cr+=compileScope(type, plen, tlen);
            buf = buf.slice(4);
            plen += tlen;
        }

        // Read the Fields
        buf = buff.slice(osLen);
        while (buf.length > 3) {
            type = buf.readUInt16BE(0);
            tlen = buf.readUInt16BE(2);
            debug('    FIELD type: %d (%s) len: %d, plen: %d', type,nfTypes[type].name,tlen,plen);
            if (type>0) cr+=compileStatement(type, plen, tlen);
            buf = buf.slice(4);
            plen += tlen;
        }
        cr+="// option "+tId+"\n";
        cr+="return o;";
        debug('option template compiled to %s',cr);
        templates[tId] = { len: plen, compiled: new Function('buf','nfTypes',cr) };
    }

    var buf = msg.slice(20);
    while (buf.length > 0) {
        var fsId = buf.readUInt16BE(0);
        var len = buf.readUInt16BE(2);
        if (fsId == 0) readTemplate(buf);
        else if (fsId == 1) readOptions(buf);
        else if (fsId > 1 && fsId < 256) {
            debug('Unknown Flowset ID %d!', fsId);
        }
        else if (fsId > 255 && typeof templates[fsId] != 'undefined') {
            var tbuf = buf.slice(4, len);
            while (tbuf.length >= templates[fsId].len) {
                out.flows.push(decodeTemplate(fsId, tbuf));
                tbuf = tbuf.slice(templates[fsId].len);
            }
        } else if (fsId > 255) {
            debug('Unknown template/option data with flowset id %d',fsId);
        }
        buf = buf.slice(len);
    }

    return out;
}

function nf1PktDecode(msg) {
    var out = { header: {
        version: msg.readUInt16BE(0),
        count: msg.readUInt16BE(2),
        uptime: msg.readUInt32BE(4),
        seconds: msg.readUInt32BE(8),
        nseconds: msg.readUInt32BE(12)
    }, flows: []};
    var buf = msg.slice(16);
    var t;
    while(buf.length>0) {
        out.flows.push({
            ipv4_src_addr: (t=buf.readUInt32BE(0),(parseInt(t/16777216)%256)+'.'+(parseInt(t/65536)%256)+'.'+(parseInt(t/256)%256)+'.'+(t%256)),
            ipv4_dst_addr: (t=buf.readUInt32BE(4),(parseInt(t/16777216)%256)+'.'+(parseInt(t/65536)%256)+'.'+(parseInt(t/256)%256)+'.'+(t%256)),
            ipv4_next_hop: (t=buf.readUInt32BE(8),(parseInt(t/16777216)%256)+'.'+(parseInt(t/65536)%256)+'.'+(parseInt(t/256)%256)+'.'+(t%256)),
            input_snmp: buf.readUInt16BE(12),
            output_snmp: buf.readUInt16BE(14),
            in_pkts: buf.readUInt32BE(16),
            in_bytes: buf.readUInt32BE(20),
            first_switched: buf.readUInt32BE(24),
            last_switched: buf.readUInt32BE(28),
            l4_src_port: buf.readUInt16BE(32),
            l4_dst_port: buf.readUInt16BE(34),
            protocol: buf.readUInt8(38),
            src_tos: buf.readUInt8(39),
            tcp_flags: buf.readUInt8(40)
        });
        buf = buf.slice(48);
    }
    return out;
}

function nf5PktDecode(msg) {
    var out = { header: {
        version: msg.readUInt16BE(0),
        count: msg.readUInt16BE(2),
        uptime: msg.readUInt32BE(4),
        seconds: msg.readUInt32BE(8),
        nseconds: msg.readUInt32BE(12),
        sequence: msg.readUInt32BE(16),
        engine_type: msg.readUInt8(20),
        engine_id: msg.readUInt8(21),
        sampling_interval: msg.readUInt16BE(22)
    }, flows: []};
    var buf = msg.slice(24);
    var t;
    while(buf.length>0) {
        out.flows.push({
            ipv4_src_addr: (t=buf.readUInt32BE(0),(parseInt(t/16777216)%256)+'.'+(parseInt(t/65536)%256)+'.'+(parseInt(t/256)%256)+'.'+(t%256)),
            ipv4_dst_addr: (t=buf.readUInt32BE(4),(parseInt(t/16777216)%256)+'.'+(parseInt(t/65536)%256)+'.'+(parseInt(t/256)%256)+'.'+(t%256)),
            ipv4_next_hop: (t=buf.readUInt32BE(8),(parseInt(t/16777216)%256)+'.'+(parseInt(t/65536)%256)+'.'+(parseInt(t/256)%256)+'.'+(t%256)),
            input_snmp: buf.readUInt16BE(12),
            output_snmp: buf.readUInt16BE(14),
            in_pkts: buf.readUInt32BE(16),
            in_bytes: buf.readUInt32BE(20),
            first_switched: buf.readUInt32BE(24),
            last_switched: buf.readUInt32BE(28),
            ipv4_src_port: buf.readUInt16BE(32),
            ipv4_dst_port: buf.readUInt16BE(34),
            tcp_flags: buf.readUInt8(37),
            protocol: buf.readUInt8(38),
            src_tos: buf.readUInt8(39),
            in_as: buf.readUInt16BE(40),
            out_as: buf.readUInt16BE(42),
            src_mask: buf.readUInt8(44),
            dst_mask: buf.readUInt8(45)
        });
        buf = buf.slice(48);
    }
    return out;
}

function nf7PktDecode(msg) {
    var out = { header: {
        version: msg.readUInt16BE(0),
        count: msg.readUInt16BE(2),
        uptime: msg.readUInt32BE(4),
        seconds: msg.readUInt32BE(8),
        nseconds: msg.readUInt32BE(12),
        sequence: msg.readUInt32BE(16)
    }, flows: []};
    var buf = msg.slice(24);
    var t;
    while(buf.length>0) {
        out.flows.push({
            ipv4_src_addr: (t=buf.readUInt32BE(0),(parseInt(t/16777216)%256)+'.'+(parseInt(t/65536)%256)+'.'+(parseInt(t/256)%256)+'.'+(t%256)),
            ipv4_dst_addr: (t=buf.readUInt32BE(4),(parseInt(t/16777216)%256)+'.'+(parseInt(t/65536)%256)+'.'+(parseInt(t/256)%256)+'.'+(t%256)),
            ipv4_next_hop: (t=buf.readUInt32BE(8),(parseInt(t/16777216)%256)+'.'+(parseInt(t/65536)%256)+'.'+(parseInt(t/256)%256)+'.'+(t%256)),
            input_snmp: buf.readUInt16BE(12),
            output_snmp: buf.readUInt16BE(14),
            in_pkts: buf.readUInt32BE(16),
            in_bytes: buf.readUInt32BE(20),
            first_switched: buf.readUInt32BE(24),
            last_switched: buf.readUInt32BE(28),
            l4_src_port: buf.readUInt16BE(32),
            l4_dst_port: buf.readUInt16BE(34),
            flags: buf.readUInt8(36),
            tcp_flags: buf.readUInt8(37),
            protocol: buf.readUInt8(38),
            src_tos: buf.readUInt8(39),
            in_as: buf.readUInt16BE(40),
            out_as: buf.readUInt16BE(42),
            src_mask: buf.readUInt8(44),
            dst_mask: buf.readUInt8(45),
            flow_flags: buf.readUInt16BE(46),
            router_sc: (t=buf.readUInt32BE(48),(parseInt(t/16777216)%256)+'.'+(parseInt(t/65536)%256)+'.'+(parseInt(t/256)%256)+'.'+(t%256))
        });
        buf = buf.slice(48);
    }
    return out;
}

function nfPktDecode(msg) {
    var version = msg.readUInt16BE(0);
    switch (version) {
        case 1:
            return this.nf1PktDecode(msg);
            break;
        case 5:
            return this.nf5PktDecode(msg);
            break;
        case 7:
            return this.nf7PktDecode(msg);
            break;
        case 9:
            return this.nf9PktDecode(msg);
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
    this.nfTypes = util._extend(nfTypes); // Inherit nfTypes
    if (options.ipv4num) decIpv4Rule[4] = "o['$name']=buf.readUInt32BE($pos);";
    this.server = dgram.createSocket('udp4');
    e.call(this,options);
    var cb = null;
    if (typeof options == 'function') cb = options; else
    if (typeof options.cb == 'function') cb = options.cb;
    this.server.on('message',function(msg,rinfo){
        if (rinfo.size<20) return;
        var o = me.nfPktDecode(msg);
        if (o && o.flows.length > 0) { // If the packet does not contain flows, only templates we do not decode
            o.rinfo = rinfo;
            o.packet = msg;
            if (cb)
                cb(o);
            else
                me.emit('data',o);
        } else debug('Undecoded flows',o);
    });
    this.listen = function(port) {
        setTimeout(function() {
            me.server.bind(port);
        },50);
    };
    if (options.port) this.listen(options.port);
}

util.inherits(NetFlowV9,e);
NetFlowV9.prototype.nfPktDecode = nfPktDecode;
NetFlowV9.prototype.nf1PktDecode = nf1PktDecode;
NetFlowV9.prototype.nf5PktDecode = nf5PktDecode;
NetFlowV9.prototype.nf7PktDecode = nf7PktDecode;
NetFlowV9.prototype.nf9PktDecode = nf9PktDecode;
module.exports = NetFlowV9;