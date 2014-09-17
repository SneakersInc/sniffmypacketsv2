#!/usr/bin/env python


from canari.maltego.message import Entity, EntityField, EntityFieldType, MatchingRule

__author__ = 'catalyst256'
__copyright__ = 'Copyright 2014, Sniffmypacketsv2 Project'
__credits__ = []

__license__ = 'GPL'
__version__ = '0.1'
__maintainer__ = 'catalyst256'
__email__ = 'catalyst256@gmail.com'
__status__ = 'Development'

__all__ = [
    'Sniffmypacketsv2Entity',
    'MySniffmypacketsv2Entity'
]

class Sniffmypacketsv2Entity(Entity):
    _namespace_ = 'sniffmypacketsv2'

# @EntityField(name='sniffmypacketsv2.fieldN', propname='fieldN', displayname='Field N', matchingrule=MatchingRule.Loose)
# @EntityField(name='sniffmypacketsv2.field1', propname='field1', displayname='Field 1', type=EntityFieldType.Integer)
class pcapFile(Sniffmypacketsv2Entity):
    pass

class SessionID(Sniffmypacketsv2Entity):
    pass

class Folder(Sniffmypacketsv2Entity):
    pass

class Host(Sniffmypacketsv2Entity):
    pass
