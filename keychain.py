import json, os
import M2Crypto
import time

class Keychain( object ):
	'''Things to do with keys'''	

	path = None
	keys = {}

	def __init__( self, path ):
		self.path = path
		try:
			with open( self.path, 'rb' ) as f:
				for k,v in json.load( f ).iteritems():
					print( 'Importing key "%s"' % k )
					self.keys[k] = M2Crypto.EVP.load_key_string( str( v ) )	
		except IOError:
			pass

	def add( self, name, key, encrypt=True ):
		if encrypt:
			self.keys[name] = key.as_pem()
		else:
			self.keys[name] = key.as_pem( cipher=None )

	def commit( self ):
		with open( self.path, 'wb' ) as f:
			json.dump( self.keys, f )

	@classmethod
	def create_identity( self ):
		'''Creates an identity certificate'''
		key = M2Crypto.RSA.gen_key( 3072, 65537 )
		identity_key = M2Crypto.EVP.PKey()
		identity_key.assign_rsa( key )
		return identity_key

	@classmethod
	def generate_certificate( self, key, identity ):
		cert = M2Crypto.X509.X509()	
		cert.set_pubkey( key )
		length = sum( map( ord, os.urandom( 5 ) ) )
		cert.set_serial_number( sum( map( ord, os.urandom( length ) ) ) )
		not_before = M2Crypto.ASN1.ASN1_UTCTIME()
		not_before.set_time( int( time.time() - 900 ) )
		cert.set_not_before( not_before )
		not_after = M2Crypto.ASN1.ASN1_UTCTIME()
		not_after.set_time( int( time.time() + 86500 + sum( map( ord, os.urandom( length ) ) ) ) )
		cert.set_not_after( not_after )
		cert.sign( identity, 'sha1' )
		return cert
