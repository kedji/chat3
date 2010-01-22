# Copyright notice:
#  (C) 2009-2010
# This software is provided 'as-is' without any express or implied warranty.
# In no event will the authors be held liable for damages arising from the
# use of this software.  All license is reserved.


# Class that manages server-side SSL.  Currently this uses a non-verifying
# key with a 10 year expiration, disseminated by a shared RSA key of 512 bits.
# Last revision:  Jan 15, 2007

# NOTE: this class is depricated for Chat 2.1 and beyond in the 2.X line
# since SSL is no-longer used.  It is used again starting with Chat 3.0

require 'socket'
require 'openssl'

class ServerSSL

  # Set up the one-time certificate
  def initialize
    @key = OpenSSL::PKey::RSA.new(512)
    @cert = OpenSSL::X509::Certificate.new
    @cert.version, @cert.serial = 2, 0
    name = OpenSSL::X509::Name.new([["C","JP"],["O","TEST"],["CN","localhost"]])
    @cert.subject = @cert.issuer = name
    @cert.not_before = Time.now
    @cert.not_after = Time.now + (3600 * 24 * 365 * 10)  # Ten-year expiration
    @cert.public_key = @key.public_key
    ef = OpenSSL::X509::ExtensionFactory.new(nil, @cert)
    @cert.extensions = [
      ef.create_extension("basicConstraints","CA:FALSE"),
      ef.create_extension("subjectKeyIdentifier","hash"),
      ef.create_extension("extendedKeyUsage","serverAuth"),
      ef.create_extension("keyUsage",
                          "keyEncipherment,dataEncipherment,digitalSignature")]
    ef.issuer_certificate = @cert
    @cert.add_extension ef.create_extension("authorityKeyIdentifier",
                                            "keyid:always,issuer:always")
    @cert.sign(@key, OpenSSL::Digest::SHA1.new)
    true
  end  # of initialize

  # Generate an SSL-ready TCPServer
  def new_server(*args)
    ctx = OpenSSL::SSL::SSLContext.new
    ctx.key, ctx.cert = @key, @cert
    tcps = TCPServer.new(*args)
    OpenSSL::SSL::SSLServer.new(tcps, ctx)
  end

  # Otherwise this returns the private key!
  def inspect
    "<ServerSSL Object>"
  end
end  # of class ServerSSL
