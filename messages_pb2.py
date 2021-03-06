# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: messages.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x0emessages.proto\"\xc6\x03\n\x0bPlayerState\x12\n\n\x02id\x18\x01 \x01(\x05\x12\x11\n\tworldTime\x18\x02 \x01(\x03\x12\x10\n\x08\x64istance\x18\x03 \x01(\x05\x12\x10\n\x08roadTime\x18\x04 \x01(\x05\x12\x0c\n\x04laps\x18\x05 \x01(\x05\x12\r\n\x05speed\x18\x06 \x01(\x05\x12\x14\n\x0croadPosition\x18\x08 \x01(\x05\x12\x12\n\ncadenceUHz\x18\t \x01(\x05\x12\x11\n\theartrate\x18\x0b \x01(\x05\x12\r\n\x05power\x18\x0c \x01(\x05\x12\x0f\n\x07heading\x18\r \x01(\x03\x12\x0c\n\x04lean\x18\x0e \x01(\x05\x12\x10\n\x08\x63limbing\x18\x0f \x01(\x05\x12\x0c\n\x04time\x18\x10 \x01(\x05\x12\x0b\n\x03\x66\x31\x39\x18\x13 \x01(\x05\x12\x0b\n\x03\x66\x32\x30\x18\x14 \x01(\x05\x12\x10\n\x08progress\x18\x15 \x01(\x05\x12\x17\n\x0f\x63ustomisationId\x18\x16 \x01(\x03\x12\x14\n\x0cjustWatching\x18\x17 \x01(\x05\x12\x10\n\x08\x63\x61lories\x18\x18 \x01(\x05\x12\t\n\x01x\x18\x19 \x01(\x02\x12\x10\n\x08\x61ltitude\x18\x1a \x01(\x02\x12\t\n\x01y\x18\x1b \x01(\x02\x12\x17\n\x0fwatchingRiderId\x18\x1c \x01(\x05\x12\x0f\n\x07groupId\x18\x1d \x01(\x05\x12\r\n\x05sport\x18\x1f \x01(\x03\"\xd1\x01\n\x0e\x43lientToServer\x12\x11\n\tconnected\x18\x01 \x01(\x05\x12\x10\n\x08rider_id\x18\x02 \x01(\x05\x12\x12\n\nworld_time\x18\x03 \x01(\x03\x12\x1b\n\x05state\x18\x07 \x01(\x0b\x32\x0c.PlayerState\x12\r\n\x05seqno\x18\x04 \x01(\x05\x12\x0c\n\x04tag8\x18\x08 \x01(\x03\x12\x0c\n\x04tag9\x18\t \x01(\x03\x12\x13\n\x0blast_update\x18\n \x01(\x03\x12\r\n\x05tag11\x18\x0b \x01(\x03\x12\x1a\n\x12last_player_update\x18\x0c \x01(\x03\"\xe2\x01\n\rSegmentResult\x12\n\n\x02id\x18\x01 \x01(\x03\x12\x10\n\x08rider_id\x18\x02 \x01(\x03\x12\x19\n\x11\x65vent_subgroup_id\x18\x06 \x01(\x03\x12\x12\n\nfirst_name\x18\x07 \x01(\t\x12\x11\n\tlast_name\x18\x08 \x01(\t\x12\x17\n\x0f\x66inish_time_str\x18\n \x01(\t\x12\x12\n\nelapsed_ms\x18\x0b \x01(\x03\x12\x12\n\npowermeter\x18\x0c \x01(\x05\x12\x0e\n\x06weight\x18\r \x01(\x05\x12\r\n\x05power\x18\x0f \x01(\x05\x12\x11\n\theartrate\x18\x13 \x01(\x05\"z\n\x0eSegmentResults\x12\x10\n\x08world_id\x18\x01 \x01(\x03\x12\x12\n\nsegment_id\x18\x02 \x01(\x03\x12\x19\n\x11\x65vent_subgroup_id\x18\x03 \x01(\x03\x12\'\n\x0fsegment_results\x18\x04 \x03(\x0b\x32\x0e.SegmentResult\"\x11\n\x0fUnknownMessage1\"\x10\n\x0eUnknownMessage\"\xe1\x01\n\x0eServerToClient\x12\x0c\n\x04tag1\x18\x01 \x01(\x05\x12\x10\n\x08rider_id\x18\x02 \x01(\x05\x12\x12\n\nworld_time\x18\x03 \x01(\x03\x12\r\n\x05seqno\x18\x04 \x01(\x05\x12#\n\rplayer_states\x18\x08 \x03(\x0b\x32\x0c.PlayerState\x12\'\n\x0eplayer_updates\x18\t \x03(\x0b\x32\x0f.UnknownMessage\x12\r\n\x05tag11\x18\x0b \x01(\x03\x12\r\n\x05tag17\x18\x11 \x01(\x03\x12\x10\n\x08num_msgs\x18\x12 \x01(\x05\x12\x0e\n\x06msgnum\x18\x13 \x01(\x05\"u\n\x0fWorldAttributes\x12\x10\n\x08world_id\x18\x01 \x01(\x05\x12\x0c\n\x04name\x18\x02 \x01(\t\x12\x0c\n\x04tag3\x18\x03 \x01(\x03\x12\x0c\n\x04tag5\x18\x04 \x01(\x03\x12\x12\n\nworld_time\x18\x06 \x01(\x03\x12\x12\n\nclock_time\x18\x07 \x01(\x03\"$\n\x0eWorldAttribute\x12\x12\n\nworld_time\x18\x02 \x01(\x03\"\xa9\x01\n\x15\x45ventSubgroupProtobuf\x12\n\n\x02id\x18\x01 \x01(\x05\x12\x0c\n\x04name\x18\x02 \x01(\t\x12\r\n\x05rules\x18\x08 \x01(\x05\x12\r\n\x05route\x18\x16 \x01(\x05\x12\x0c\n\x04laps\x18\x19 \x01(\x05\x12\x15\n\rstartLocation\x18\x1d \x01(\x05\x12\r\n\x05label\x18\x1e \x01(\x05\x12\x10\n\x08paceType\x18\x1f \x01(\x05\x12\x12\n\njerseyHash\x18$ \x01(\x05\"\xf1\x01\n\x0fRiderAttributes\x12\n\n\x02\x66\x32\x18\x02 \x01(\x05\x12\n\n\x02\x66\x33\x18\x03 \x01(\x05\x12;\n\x10\x61ttributeMessage\x18\x04 \x01(\x0b\x32!.RiderAttributes.AttributeMessage\x12\x0f\n\x07theirId\x18\n \x01(\x05\x12\x0b\n\x03\x66\x31\x33\x18\r \x01(\x05\x1ak\n\x10\x41ttributeMessage\x12\x0c\n\x04myId\x18\x01 \x01(\x05\x12\x0f\n\x07theirId\x18\x02 \x01(\x05\x12\x11\n\tfirstName\x18\x03 \x01(\t\x12\x10\n\x08lastName\x18\x04 \x01(\t\x12\x13\n\x0b\x63ountryCode\x18\x05 \x01(\x05\"&\n\x08Profiles\x12\x1a\n\x08profiles\x18\x01 \x03(\x0b\x32\x08.Profile\"\x8a\x03\n\x07Profile\x12\n\n\x02id\x18\x01 \x01(\x05\x12\x11\n\tfirstName\x18\x04 \x01(\t\x12\x10\n\x08lastName\x18\x05 \x01(\t\x12\x0c\n\x04male\x18\x06 \x01(\x05\x12\x0e\n\x06weight\x18\t \x01(\x05\x12\x10\n\x08\x62odyType\x18\x0c \x01(\x05\x12\x13\n\x0b\x63ountryCode\x18\" \x01(\x05\x12\x15\n\rtotalDistance\x18# \x01(\x05\x12\x1c\n\x14totalDistanceClimbed\x18$ \x01(\x05\x12\x1a\n\x12totalTimeInMinutes\x18% \x01(\x05\x12\x16\n\x0etotalWattHours\x18) \x01(\x05\x12\x0e\n\x06height\x18* \x01(\x05\x12\x1d\n\x15totalExperiencePoints\x18. \x01(\x05\x12\x18\n\x10\x61\x63hievementLevel\x18\x31 \x01(\x05\x12\x13\n\x0bpowerSource\x18\x34 \x01(\x05\x12\x0b\n\x03\x61ge\x18\x37 \x01(\x05\x12\x1a\n\x12launchedGameClient\x18l \x01(\t\x12\x19\n\x11\x63urrentActivityId\x18m \x01(\x05\"*\n\x07Vector3\x12\t\n\x01x\x18\x01 \x01(\x02\x12\t\n\x01y\x18\x02 \x01(\x02\x12\t\n\x01z\x18\x03 \x01(\x02\"\xad\x01\n\nPlayerInfo\x12\n\n\x02id\x18\x01 \x01(\x05\x12\n\n\x02\x66\x32\x18\x02 \x01(\x05\x12\x1a\n\x08position\x18\x03 \x01(\x0b\x32\x08.Vector3\x12\x0f\n\x07profile\x18\x05 \x01(\t\x12\x0b\n\x03id2\x18\x06 \x01(\x05\x12\n\n\x02\x66\x37\x18\x07 \x01(\x05\x12\x0c\n\x04name\x18\x0b \x01(\t\x12\x13\n\x0b\x63ountryCode\x18\x0c \x01(\x05\x12\x11\n\tworldTime\x18\r \x01(\x07\x12\x0b\n\x03\x66\x31\x36\x18\x10 \x01(\x05\"I\n\nGTPC21_6_1\x12\r\n\x05seqno\x18\x01 \x01(\x05\x12 \n\x0bplayerInfos\x18\x02 \x03(\x0b\x32\x0b.PlayerInfo\x12\n\n\x02\x66\x33\x18\x03 \x01(\x05\"+\n\x08GTPC21_6\x12\x1f\n\ngtpc21_6_1\x18\x01 \x03(\x0b\x32\x0b.GTPC21_6_1\":\n\x08GTPC21_4\x12\n\n\x02\x66\x31\x18\x01 \x01(\x05\x12\n\n\x02\x66\x36\x18\x06 \x01(\t\x12\n\n\x02\x66\x37\x18\x07 \x01(\x05\x12\n\n\x02\x66\x38\x18\x08 \x01(\x05\"\"\n\x08GTPC21_8\x12\n\n\x02\x66\x31\x18\x01 \x01(\x05\x12\n\n\x02\x66\x32\x18\x02 \x01(\x05\"k\n\x06GTPC21\x12\n\n\x02\x66\x31\x18\x01 \x01(\x05\x12\x1b\n\x08gtpc21_4\x18\x04 \x01(\x0b\x32\t.GTPC21_4\x12\x1b\n\x08gtpc21_6\x18\x06 \x01(\x0b\x32\t.GTPC21_6\x12\x1b\n\x08gtpc21_8\x18\x08 \x01(\x0b\x32\t.GTPC21_8\"H\n\x12GameToPhoneCommand\x12\r\n\x05seqno\x18\x01 \x01(\x05\x12\n\n\x02\x66\x32\x18\x02 \x01(\x05\x12\x17\n\x06gtpc21\x18\x15 \x01(\x0b\x32\x07.GTPC21\"|\n\x0bGameToPhone\x12\n\n\x02\x66\x31\x18\x01 \x01(\x05\x12\n\n\x02\x66\x32\x18\x02 \x01(\x05\x12\n\n\x02id\x18\x03 \x01(\x05\x12\n\n\x02\x66\x34\x18\x04 \x01(\x05\x12\n\n\x02\x66\x36\x18\x06 \x01(\x05\x12\n\n\x02\x66\x37\x18\x07 \x01(\x05\x12%\n\x08\x63ommands\x18\x0b \x03(\x0b\x32\x13.GameToPhoneCommand\"f\n\rZMLClientInfo\x12\x12\n\nappVersion\x18\x01 \x01(\t\x12\x17\n\x0fsystemOSVersion\x18\x02 \x01(\t\x12\x10\n\x08systemOS\x18\x03 \x01(\t\x12\x16\n\x0esystemHardware\x18\x04 \x01(\t\"A\n\x15ZMLClientCapabilities\x12\n\n\x02\x66\x31\x18\x01 \x01(\x05\x12\x1c\n\x04info\x18\x05 \x01(\x0b\x32\x0e.ZMLClientInfo\"\xa9\x01\n\x12PhoneToGameCommand\x12\r\n\x05seqno\x18\x01 \x01(\x05\x12\x0f\n\x07\x63ommand\x18\x02 \x01(\x05\x12\x0f\n\x07subject\x18\x03 \x01(\x05\x12\n\n\x02\x66\x35\x18\x05 \x01(\x05\x12\n\n\x02\x66\x36\x18\x06 \x01(\t\x12\n\n\x02\x66\x37\x18\x07 \x01(\x05\x12\x10\n\x08playerId\x18\x13 \x01(\x05\x12,\n\x0c\x63\x61pabilities\x18\x15 \x01(\x0b\x32\x16.ZMLClientCapabilities\"L\n\x0bPhoneToGame\x12\n\n\x02id\x18\x01 \x01(\x05\x12$\n\x07\x63ommand\x18\x02 \x01(\x0b\x32\x13.PhoneToGameCommand\x12\x0b\n\x03\x66\x31\x30\x18\n \x01(\x05\x62\x06proto3')



_PLAYERSTATE = DESCRIPTOR.message_types_by_name['PlayerState']
_CLIENTTOSERVER = DESCRIPTOR.message_types_by_name['ClientToServer']
_SEGMENTRESULT = DESCRIPTOR.message_types_by_name['SegmentResult']
_SEGMENTRESULTS = DESCRIPTOR.message_types_by_name['SegmentResults']
_UNKNOWNMESSAGE1 = DESCRIPTOR.message_types_by_name['UnknownMessage1']
_UNKNOWNMESSAGE = DESCRIPTOR.message_types_by_name['UnknownMessage']
_SERVERTOCLIENT = DESCRIPTOR.message_types_by_name['ServerToClient']
_WORLDATTRIBUTES = DESCRIPTOR.message_types_by_name['WorldAttributes']
_WORLDATTRIBUTE = DESCRIPTOR.message_types_by_name['WorldAttribute']
_EVENTSUBGROUPPROTOBUF = DESCRIPTOR.message_types_by_name['EventSubgroupProtobuf']
_RIDERATTRIBUTES = DESCRIPTOR.message_types_by_name['RiderAttributes']
_RIDERATTRIBUTES_ATTRIBUTEMESSAGE = _RIDERATTRIBUTES.nested_types_by_name['AttributeMessage']
_PROFILES = DESCRIPTOR.message_types_by_name['Profiles']
_PROFILE = DESCRIPTOR.message_types_by_name['Profile']
_VECTOR3 = DESCRIPTOR.message_types_by_name['Vector3']
_PLAYERINFO = DESCRIPTOR.message_types_by_name['PlayerInfo']
_GTPC21_6_1 = DESCRIPTOR.message_types_by_name['GTPC21_6_1']
_GTPC21_6 = DESCRIPTOR.message_types_by_name['GTPC21_6']
_GTPC21_4 = DESCRIPTOR.message_types_by_name['GTPC21_4']
_GTPC21_8 = DESCRIPTOR.message_types_by_name['GTPC21_8']
_GTPC21 = DESCRIPTOR.message_types_by_name['GTPC21']
_GAMETOPHONECOMMAND = DESCRIPTOR.message_types_by_name['GameToPhoneCommand']
_GAMETOPHONE = DESCRIPTOR.message_types_by_name['GameToPhone']
_ZMLCLIENTINFO = DESCRIPTOR.message_types_by_name['ZMLClientInfo']
_ZMLCLIENTCAPABILITIES = DESCRIPTOR.message_types_by_name['ZMLClientCapabilities']
_PHONETOGAMECOMMAND = DESCRIPTOR.message_types_by_name['PhoneToGameCommand']
_PHONETOGAME = DESCRIPTOR.message_types_by_name['PhoneToGame']
PlayerState = _reflection.GeneratedProtocolMessageType('PlayerState', (_message.Message,), {
  'DESCRIPTOR' : _PLAYERSTATE,
  '__module__' : 'messages_pb2'
  # @@protoc_insertion_point(class_scope:PlayerState)
  })
_sym_db.RegisterMessage(PlayerState)

ClientToServer = _reflection.GeneratedProtocolMessageType('ClientToServer', (_message.Message,), {
  'DESCRIPTOR' : _CLIENTTOSERVER,
  '__module__' : 'messages_pb2'
  # @@protoc_insertion_point(class_scope:ClientToServer)
  })
_sym_db.RegisterMessage(ClientToServer)

SegmentResult = _reflection.GeneratedProtocolMessageType('SegmentResult', (_message.Message,), {
  'DESCRIPTOR' : _SEGMENTRESULT,
  '__module__' : 'messages_pb2'
  # @@protoc_insertion_point(class_scope:SegmentResult)
  })
_sym_db.RegisterMessage(SegmentResult)

SegmentResults = _reflection.GeneratedProtocolMessageType('SegmentResults', (_message.Message,), {
  'DESCRIPTOR' : _SEGMENTRESULTS,
  '__module__' : 'messages_pb2'
  # @@protoc_insertion_point(class_scope:SegmentResults)
  })
_sym_db.RegisterMessage(SegmentResults)

UnknownMessage1 = _reflection.GeneratedProtocolMessageType('UnknownMessage1', (_message.Message,), {
  'DESCRIPTOR' : _UNKNOWNMESSAGE1,
  '__module__' : 'messages_pb2'
  # @@protoc_insertion_point(class_scope:UnknownMessage1)
  })
_sym_db.RegisterMessage(UnknownMessage1)

UnknownMessage = _reflection.GeneratedProtocolMessageType('UnknownMessage', (_message.Message,), {
  'DESCRIPTOR' : _UNKNOWNMESSAGE,
  '__module__' : 'messages_pb2'
  # @@protoc_insertion_point(class_scope:UnknownMessage)
  })
_sym_db.RegisterMessage(UnknownMessage)

ServerToClient = _reflection.GeneratedProtocolMessageType('ServerToClient', (_message.Message,), {
  'DESCRIPTOR' : _SERVERTOCLIENT,
  '__module__' : 'messages_pb2'
  # @@protoc_insertion_point(class_scope:ServerToClient)
  })
_sym_db.RegisterMessage(ServerToClient)

WorldAttributes = _reflection.GeneratedProtocolMessageType('WorldAttributes', (_message.Message,), {
  'DESCRIPTOR' : _WORLDATTRIBUTES,
  '__module__' : 'messages_pb2'
  # @@protoc_insertion_point(class_scope:WorldAttributes)
  })
_sym_db.RegisterMessage(WorldAttributes)

WorldAttribute = _reflection.GeneratedProtocolMessageType('WorldAttribute', (_message.Message,), {
  'DESCRIPTOR' : _WORLDATTRIBUTE,
  '__module__' : 'messages_pb2'
  # @@protoc_insertion_point(class_scope:WorldAttribute)
  })
_sym_db.RegisterMessage(WorldAttribute)

EventSubgroupProtobuf = _reflection.GeneratedProtocolMessageType('EventSubgroupProtobuf', (_message.Message,), {
  'DESCRIPTOR' : _EVENTSUBGROUPPROTOBUF,
  '__module__' : 'messages_pb2'
  # @@protoc_insertion_point(class_scope:EventSubgroupProtobuf)
  })
_sym_db.RegisterMessage(EventSubgroupProtobuf)

RiderAttributes = _reflection.GeneratedProtocolMessageType('RiderAttributes', (_message.Message,), {

  'AttributeMessage' : _reflection.GeneratedProtocolMessageType('AttributeMessage', (_message.Message,), {
    'DESCRIPTOR' : _RIDERATTRIBUTES_ATTRIBUTEMESSAGE,
    '__module__' : 'messages_pb2'
    # @@protoc_insertion_point(class_scope:RiderAttributes.AttributeMessage)
    })
  ,
  'DESCRIPTOR' : _RIDERATTRIBUTES,
  '__module__' : 'messages_pb2'
  # @@protoc_insertion_point(class_scope:RiderAttributes)
  })
_sym_db.RegisterMessage(RiderAttributes)
_sym_db.RegisterMessage(RiderAttributes.AttributeMessage)

Profiles = _reflection.GeneratedProtocolMessageType('Profiles', (_message.Message,), {
  'DESCRIPTOR' : _PROFILES,
  '__module__' : 'messages_pb2'
  # @@protoc_insertion_point(class_scope:Profiles)
  })
_sym_db.RegisterMessage(Profiles)

Profile = _reflection.GeneratedProtocolMessageType('Profile', (_message.Message,), {
  'DESCRIPTOR' : _PROFILE,
  '__module__' : 'messages_pb2'
  # @@protoc_insertion_point(class_scope:Profile)
  })
_sym_db.RegisterMessage(Profile)

Vector3 = _reflection.GeneratedProtocolMessageType('Vector3', (_message.Message,), {
  'DESCRIPTOR' : _VECTOR3,
  '__module__' : 'messages_pb2'
  # @@protoc_insertion_point(class_scope:Vector3)
  })
_sym_db.RegisterMessage(Vector3)

PlayerInfo = _reflection.GeneratedProtocolMessageType('PlayerInfo', (_message.Message,), {
  'DESCRIPTOR' : _PLAYERINFO,
  '__module__' : 'messages_pb2'
  # @@protoc_insertion_point(class_scope:PlayerInfo)
  })
_sym_db.RegisterMessage(PlayerInfo)

GTPC21_6_1 = _reflection.GeneratedProtocolMessageType('GTPC21_6_1', (_message.Message,), {
  'DESCRIPTOR' : _GTPC21_6_1,
  '__module__' : 'messages_pb2'
  # @@protoc_insertion_point(class_scope:GTPC21_6_1)
  })
_sym_db.RegisterMessage(GTPC21_6_1)

GTPC21_6 = _reflection.GeneratedProtocolMessageType('GTPC21_6', (_message.Message,), {
  'DESCRIPTOR' : _GTPC21_6,
  '__module__' : 'messages_pb2'
  # @@protoc_insertion_point(class_scope:GTPC21_6)
  })
_sym_db.RegisterMessage(GTPC21_6)

GTPC21_4 = _reflection.GeneratedProtocolMessageType('GTPC21_4', (_message.Message,), {
  'DESCRIPTOR' : _GTPC21_4,
  '__module__' : 'messages_pb2'
  # @@protoc_insertion_point(class_scope:GTPC21_4)
  })
_sym_db.RegisterMessage(GTPC21_4)

GTPC21_8 = _reflection.GeneratedProtocolMessageType('GTPC21_8', (_message.Message,), {
  'DESCRIPTOR' : _GTPC21_8,
  '__module__' : 'messages_pb2'
  # @@protoc_insertion_point(class_scope:GTPC21_8)
  })
_sym_db.RegisterMessage(GTPC21_8)

GTPC21 = _reflection.GeneratedProtocolMessageType('GTPC21', (_message.Message,), {
  'DESCRIPTOR' : _GTPC21,
  '__module__' : 'messages_pb2'
  # @@protoc_insertion_point(class_scope:GTPC21)
  })
_sym_db.RegisterMessage(GTPC21)

GameToPhoneCommand = _reflection.GeneratedProtocolMessageType('GameToPhoneCommand', (_message.Message,), {
  'DESCRIPTOR' : _GAMETOPHONECOMMAND,
  '__module__' : 'messages_pb2'
  # @@protoc_insertion_point(class_scope:GameToPhoneCommand)
  })
_sym_db.RegisterMessage(GameToPhoneCommand)

GameToPhone = _reflection.GeneratedProtocolMessageType('GameToPhone', (_message.Message,), {
  'DESCRIPTOR' : _GAMETOPHONE,
  '__module__' : 'messages_pb2'
  # @@protoc_insertion_point(class_scope:GameToPhone)
  })
_sym_db.RegisterMessage(GameToPhone)

ZMLClientInfo = _reflection.GeneratedProtocolMessageType('ZMLClientInfo', (_message.Message,), {
  'DESCRIPTOR' : _ZMLCLIENTINFO,
  '__module__' : 'messages_pb2'
  # @@protoc_insertion_point(class_scope:ZMLClientInfo)
  })
_sym_db.RegisterMessage(ZMLClientInfo)

ZMLClientCapabilities = _reflection.GeneratedProtocolMessageType('ZMLClientCapabilities', (_message.Message,), {
  'DESCRIPTOR' : _ZMLCLIENTCAPABILITIES,
  '__module__' : 'messages_pb2'
  # @@protoc_insertion_point(class_scope:ZMLClientCapabilities)
  })
_sym_db.RegisterMessage(ZMLClientCapabilities)

PhoneToGameCommand = _reflection.GeneratedProtocolMessageType('PhoneToGameCommand', (_message.Message,), {
  'DESCRIPTOR' : _PHONETOGAMECOMMAND,
  '__module__' : 'messages_pb2'
  # @@protoc_insertion_point(class_scope:PhoneToGameCommand)
  })
_sym_db.RegisterMessage(PhoneToGameCommand)

PhoneToGame = _reflection.GeneratedProtocolMessageType('PhoneToGame', (_message.Message,), {
  'DESCRIPTOR' : _PHONETOGAME,
  '__module__' : 'messages_pb2'
  # @@protoc_insertion_point(class_scope:PhoneToGame)
  })
_sym_db.RegisterMessage(PhoneToGame)

if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _PLAYERSTATE._serialized_start=19
  _PLAYERSTATE._serialized_end=473
  _CLIENTTOSERVER._serialized_start=476
  _CLIENTTOSERVER._serialized_end=685
  _SEGMENTRESULT._serialized_start=688
  _SEGMENTRESULT._serialized_end=914
  _SEGMENTRESULTS._serialized_start=916
  _SEGMENTRESULTS._serialized_end=1038
  _UNKNOWNMESSAGE1._serialized_start=1040
  _UNKNOWNMESSAGE1._serialized_end=1057
  _UNKNOWNMESSAGE._serialized_start=1059
  _UNKNOWNMESSAGE._serialized_end=1075
  _SERVERTOCLIENT._serialized_start=1078
  _SERVERTOCLIENT._serialized_end=1303
  _WORLDATTRIBUTES._serialized_start=1305
  _WORLDATTRIBUTES._serialized_end=1422
  _WORLDATTRIBUTE._serialized_start=1424
  _WORLDATTRIBUTE._serialized_end=1460
  _EVENTSUBGROUPPROTOBUF._serialized_start=1463
  _EVENTSUBGROUPPROTOBUF._serialized_end=1632
  _RIDERATTRIBUTES._serialized_start=1635
  _RIDERATTRIBUTES._serialized_end=1876
  _RIDERATTRIBUTES_ATTRIBUTEMESSAGE._serialized_start=1769
  _RIDERATTRIBUTES_ATTRIBUTEMESSAGE._serialized_end=1876
  _PROFILES._serialized_start=1878
  _PROFILES._serialized_end=1916
  _PROFILE._serialized_start=1919
  _PROFILE._serialized_end=2313
  _VECTOR3._serialized_start=2315
  _VECTOR3._serialized_end=2357
  _PLAYERINFO._serialized_start=2360
  _PLAYERINFO._serialized_end=2533
  _GTPC21_6_1._serialized_start=2535
  _GTPC21_6_1._serialized_end=2608
  _GTPC21_6._serialized_start=2610
  _GTPC21_6._serialized_end=2653
  _GTPC21_4._serialized_start=2655
  _GTPC21_4._serialized_end=2713
  _GTPC21_8._serialized_start=2715
  _GTPC21_8._serialized_end=2749
  _GTPC21._serialized_start=2751
  _GTPC21._serialized_end=2858
  _GAMETOPHONECOMMAND._serialized_start=2860
  _GAMETOPHONECOMMAND._serialized_end=2932
  _GAMETOPHONE._serialized_start=2934
  _GAMETOPHONE._serialized_end=3058
  _ZMLCLIENTINFO._serialized_start=3060
  _ZMLCLIENTINFO._serialized_end=3162
  _ZMLCLIENTCAPABILITIES._serialized_start=3164
  _ZMLCLIENTCAPABILITIES._serialized_end=3229
  _PHONETOGAMECOMMAND._serialized_start=3232
  _PHONETOGAMECOMMAND._serialized_end=3401
  _PHONETOGAME._serialized_start=3403
  _PHONETOGAME._serialized_end=3479
# @@protoc_insertion_point(module_scope)
