import struct

# The main container for all Tor packets
# - a cell.

class Commands( object ):
	PADDING      = 0 # Padding
	CREATE       = 1 # Create a circuit
	CREATED      = 2 # Acknowledge create
	RELAY        = 3 # End-to-end data
	DESTROY      = 4 # Stop using circuit
	CREATE_FAST  = 5 # Create a circuit, no PK
	CREATED_FAST = 6 # Circuit created, no PK
	VERSIONS     = 7 # Negotiate proto version
	NEINFO       = 8 # Time and address info
	RELAY_EARLY  = 9 # En-to-end data, limited
	CREATE2      = 10 # Extended CREATE cell
	CREATED2     = 11 # Extended CREATED cell

	VPADDING       = 0x80 # Variable-length padding
	CERTS          = 0x81 # Certificates
	AUTH_CHALLENGE = 0x82 # Callenge value
	AUTHENTICATE   = 0x83 # Client authentication
	AUTHORIZE      = 0x84 # Client authorization (not yet used)

class Command( object ):
	command = None
	payload = None

	def __init__( self, payload ):
		self.payload = payload

	def bytes( self ):
		return self.payload

class VersionsCommand( Command ):
	command = Commands.VERSIONS
	versions = []

	def __init__( self, versions ):
		self.versions = versions
		payload = struct.pack( '!' + ( 'H' * len( versions ) ), *versions )
		Command.__init__( self, payload )

class Cell( object ):
	circuit_id = None
	command = None
	
	def __init__( self, circuit_id, command ):
		'''Create a cell'''
		self.circuit_id = circuit_id
		self.command = command

	def bytes( self ):
		circuit_id = 0 if not self.circuit_id else self.circuit_id
		payload = self.command.bytes()
		return struct.pack( '!HBH', circuit_id, self.command.command, len( payload ) ) + payload

	@classmethod
	def parse( self, data ):
		pass		
