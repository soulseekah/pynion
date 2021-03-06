import struct
import M2Crypto

# The main container for all Tor packets
# - a cell.

class CertificateType( object ):
	TLS_LINK  = 1
	ID_1024   = 2
	AUTH_1024 = 3

class Commands( object ):
	PADDING      = 0 # Padding
	CREATE       = 1 # Create a circuit
	CREATED      = 2 # Acknowledge create
	RELAY        = 3 # End-to-end data
	DESTROY      = 4 # Stop using circuit
	CREATE_FAST  = 5 # Create a circuit, no PK
	CREATED_FAST = 6 # Circuit created, no PK
	VERSIONS     = 7 # Negotiate proto version
	NETINFO      = 8 # Time and address info
	RELAY_EARLY  = 9 # En-to-end data, limited
	CREATE2      = 10 # Extended CREATE cell
	CREATED2     = 11 # Extended CREATED cell

	VPADDING       = 0x80 # Variable-length padding
	CERTS          = 0x81 # Certificates
	AUTH_CHALLENGE = 0x82 # Callenge value
	AUTHENTICATE   = 0x83 # Client authentication
	AUTHORIZE      = 0x84 # Client authorization (not yet used)

	@classmethod
	def byid( self, command ):
		'''Returns a Command class for an ID'''
		return {
			self.PADDING: PaddingCommand,
			self.NETINFO: NetInfoCommand,
			self.VERSIONS: VersionsCommand,
			self.CERTS: CertificatesCommand,
			self.AUTH_CHALLENGE: AuthChallengeCommand,
		}.get( command, Command )

class Command( object ):
	command = None
	payload = None

	def __init__( self, payload ):
		self.payload = payload

	def bytes( self ):
		return self.payload

	@classmethod
	def parse( self, data ):
		return self( data )

class PaddingCommand( Command ):
	command = Commands.PADDING

class NetInfoCommand( Command ):
	command = Commands.NETINFO
		
class VersionsCommand( Command ):
	command = Commands.VERSIONS
	versions = []

	def __init__( self, versions ):
		self.versions = versions
		payload = struct.pack( '!' + ( 'H' * len( versions ) ), *versions )
		Command.__init__( self, payload )
	
	@classmethod
	def parse( self, data ):
		versions = []
		while data:
			versions.append( struct.unpack( '!H', data[:2] )[0] )
			data = data[2:]
		return self( versions )
	
	def __repr__( self ):
		return 'Versions: %s' % ', '.join( map( str, self.versions ) )

class CertificatesCommand( Command ):
	command = Commands.CERTS
	certificates = {}

	def __init__( self, certificates ):
		self.certificates = certificates

	@classmethod
	def parse( self, data ):
		n = struct.unpack( '!B', data[0] )[0]
		data = data[1:]
		certificates = {}
		while data:
			ctype, length = struct.unpack( '!BH', data[0:3] )
			ctype = [ None, CertificateType.TLS_LINK, CertificateType.ID_1024, CertificateType.AUTH_1024 ][ctype]
			certificate = data[3:3+length]
			data = data[3+length:]
			certificates[ctype] = M2Crypto.X509.load_cert_der_string( certificate )
		return self( certificates )
	
	def __repr__( self ):
		def _printcertid( cert ):
			if not cert: return None
			return cert.get_fingerprint()
		return 'Link: %s, ID: %s, Auth: %s' % \
			tuple( map( _printcertid, ( self.certificates.get( CertificateType.TLS_LINK, None ),
			self.certificates.get( CertificateType.ID_1024, None ),
			self.certificates.get( CertificateType.AUTH_1024, None ) ) ) )

class AuthChallengeCommand( Command ):
	command = Commands.AUTH_CHALLENGE

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

	def send( self, writable ):
		return writable.write( self.bytes() )

	@classmethod
	def parse( self, data ):
		cells = []
		
		while data:
			try:
				circuit_id, command, payload_length = struct.unpack( '!HBH', data[:5] )
				payload = data[5:5 + payload_length]
				cells.append( Cell( circuit_id, Commands.byid( command ).parse( payload ) ) )
			except struct.error:
				break
			data = data[5 + payload_length:]
		return cells, data
