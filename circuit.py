import socket, ssl
import tempfile
import cell

# One can pretty much build arbitrary circuits
# with any number or nodes in any combination

class Circuit( object ):
	'''Building and evaluating circuits'''

	path = []
	ciphers = 'DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:DHE-RSA-3DES-CBC3-SHA'

	def auto( self, routers, length=3 ):
		'''Automatically build a circuit'''
		raise NotImplementedError()

	def add( self, router, ciphers=None ):
		if not ciphers:
			ciphers = self.ciphers
		self.path.append( Node( router, ciphers ) )

	def build( self, timeout=3.0 ):
		'''Build the cicuit using v2 or v3 handshakes'''
		for hop in self.path:
			s = socket.socket( socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP )
			s.settimeout( timeout )
			ss = ssl.wrap_socket( s, ssl_version=ssl.PROTOCOL_SSLv23, ciphers=hop.ciphers + ':NULL-MD5' )
			ss.connect( ( hop.router.address, hop.router.orport ) )
			hop.set_socket( ss )

			# Get version and certificates
			cell.Cell( None, cell.VersionsCommand( [ 3 ] ) ).send( hop.socket )
			pushback = ''
			while True:
				try:
					cells, pushback = cell.Cell.parse( ( pushback or '' ) + hop.socket.read() )
					cells = filter( lambda x: not isinstance( x, cell.PaddingCommand ), map( lambda x: x.command, cells ) )
					if cells:
						print( cells )
				except ( ssl.SSLError, socket.timeout ):
					break

	@classmethod
	def is_good_exit( self, router ):
		return 'Exit' in router.flags


class Node( object ):
	'''A node is a wrapper around a router'''

	router = None
	ciphers = None
	socket = None
	versions = None
	certificates = None

	def __init__( self, router, ciphers=Circuit.ciphers ):
		self.router = router
		self.ciphers = ciphers

	def set_socket( self, socket ):
		self.socket = socket
	
	def set_versions( self, versions ):
		versions
	
	def set_certificates( self, certificates ):
		certificates
