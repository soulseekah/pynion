import requests
import arrow
import StringIO

# Everything related to directories

# Other valid authorities, as recommended by Tor
#
# 86.59.21.38:80		tor26
# 128.31.0.34:9031		moria1
# 216.224.124.114:9030	ides
# 80.190.246.100:80		gabelmoo
# 140.247.60.64:80		lefkada
# 194.109.206.212:80	dizum
# 128.31.0.34:9032		moria2
# 213.73.91.31:80		dannenberg
# 208.83.223.34:443		urras
#
# You can also get authorities from the consensus
# sources attribute

DEFAULT_AUTHORITY = 'tor.noreply.org'

class Router( object ):
	'''A Tor router'''

	nickname = None
	identity = None
	descriptor = None
	published = None
	address = None
	orport = None
	dirport = None
	flags = []
	version = None
	bandwidth = None
	portlist = None

	def __init__( self, nickname, identity, descriptor, published, address, orport, dirport, flags, version, bandwidth, portlist ):
		self.nickname = nickname
		self.identity = identity
		self.descriptor = descriptor
		self.published = published
		self.address = address
		self.orport = orport
		self.dirport = dirport
		self.flags = flags
		self.version = version
		self.bandwidth = bandwidth
		self.portlist = portlist

class Consensus( object ):
	'''A consensus document describing the status of the network'''

	version = 3
	routers = []
	client_versions = []
	server_versions = []
	known_flags = []

	valid_after = None
	fresh_until = None
	valid_until = None

	sources = []

	@classmethod
	def parse( self, data ):
		consensus = self()
		databuffer = StringIO.StringIO( data )
		for line in databuffer:
			try:
				keyword, arguments = line.split( ' ', 1 )
			except ValueError:
				continue
			processor = '_process_%s' % keyword.replace( '-', '_' )
			if hasattr( consensus, processor ):
				databuffer = getattr( consensus, processor )( keyword, arguments, databuffer )
		return consensus

	def _process_network_status_version( self, keyword, arguments, databuffer ):
		if arguments.strip() != str( self.version ):
			raise Exception( 'Incorrect network-status-version %s' % arguments.strip() )
		return databuffer
	
	def _process_valid_after( self, keyword, arguments, databuffer ):
		self.valid_after = arrow.get( arguments.strip() )
		return databuffer

	def _process_valid_until( self, keyword, arguments, databuffer ):
		self.valid_until = arrow.get( arguments.strip() )
		return databuffer

	def _process_fresh_until( self, keyword, arguments, databuffer ):
		self.fresh_until = arrow.get( arguments.strip() )
		return databuffer

	def _process_client_versions( self, keyword, arguments, databuffer ):
		self.client_versions = arguments.strip().split( ',' )
		return databuffer

	def _process_server_versions( self, keyword, arguments, databuffer ):
		self.server_versions = arguments.strip().split( ',' )
		return databuffer

	def _process_known_flags( self, keyword, arguments, databuffer ):
		self.known_flags = arguments.strip().split( ' ' )
		return databuffer

	def _process_dir_source( self, keyword, arguments, databuffer ):
		nickname, fingerprint, hostname, address, dirport, orport = arguments.strip().split( ' ' )
		contact = databuffer.next().split( ' ', 1 )[1].strip()
		digest = databuffer.next().split( ' ', 1 )[1].strip()
		self.sources.append( {
			'nickname': nickname,
			'fingerprint': fingerprint,
			'hostname': hostname,
			'address': address,
			'dirport': int( dirport ) or None,
			'orport': int( orport ) or None,
			'contact': contact,
			'digest': digest,
		} )
		return databuffer

	def _process_r( self, keyword, arguments, databuffer ):
		nickname, identity, descriptor, date, time, address, orport, dirport = arguments.strip().split( ' ')
		version = None

		while True:
			line = databuffer.next()
			try:
				keyword, arguments = line.split( ' ', 1 )
				if keyword == 'r':
					databuffer.seek( -len( line ), 1 )
					break
			except ValueError:
				databuffer.seek( -len( line ), 1 )
				break
			if keyword == 's':
				flags = arguments.strip().split( ' ')
			elif keyword == 'v':
				version = arguments.strip()
			elif keyword == 'w':
				bandwidth = arguments.strip()
			elif keyword == 'p':
				portlist = arguments.strip()	

		self.routers.append( Router( **{
			'nickname': nickname,
			'identity': identity,
			'descriptor': descriptor,
			'published': arrow.get( '%s %s' % ( date, time ) ),
			'address': address,
			'orport': int( orport ) or None,
			'dirport': int( dirport ) or None,
			'flags': flags,
			'version': version,
			'bandwidth': bandwidth,
			'portlist': portlist
		} ) )
		return databuffer

	def _process_directory_signature( self, keyword, arguments, databuffer ):
		identity, digest = arguments.strip().split( ' ' )

		for i, source in enumerate( self.sources ):
			if source['fingerprint'] == identity:
				line = databuffer.next()
				self.sources[i]['signature'] = ''
				if not '-----BEGIN SIGNATURE-----' in line:
					databuffer.seek( -len( line ), 1 )
					break
				while True:
					line = databuffer.next()
					if '-----END SIGNATURE-----' in line:
						break
					self.sources[i]['signature'] = self.sources[i]['signature'] + line.strip()
				break
		
		return databuffer

class Authority( object ):
	'''A directory authority'''

	address = None

	def __init__( self, address=DEFAULT_AUTHORITY ):
		self.address = address

	def get_consensus( self ):
		'''Retrieves the Consensus document'''
		response = requests.get( 'http://%s/tor/status-vote/current/consensus' % self.address )
		return Consensus.parse( response.text )
