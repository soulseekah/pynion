import socket, ssl
import tempfile

# One can pretty much build arbitrary circuits
# with any number or nodes in any combination

class Node( object ):
	'''A node'''

	router = None
	ciphers = None
	socket = None

	def __init__( self, router, ciphers=Circuit.ciphers ):
		self.router = router
		self.ciphers = ciphers

	def set_socket( self, socket ):
		self.socket = socket
		

class Circuit( object ):
	'''Building and evaluating circuits'''

	path = []
	ciphers = 'DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:DHE-RSA-3DES-CBC3-SHA'

	def auto( self, routers, length=3 ):
		'''Automatically build a circuit'''
		raise NotImplementedError()

	def add( self, router, ciphers=self.ciphers ):
		self.path.append( Node( router, ciphers ) )

	def build( self ):
		'''Build the cicuit using v2 or v3 handshakes'''
		for hop in path:
			s = socket.socket( socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP )
			ss = ssl.wrap_socket( s, ssl_version=ssl.PROTOCOL_SSLv3, ciphers=hop.ciphers + ':NULL-MD5' )
			ss.connect( ( hop.router.address, hop.router.orport ) )
			hop.socket = ss

	@classpath
	def is_good_exit( self, router ):
		return 'Exit' in router.flags
