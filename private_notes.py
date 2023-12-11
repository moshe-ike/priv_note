import pickle
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import exceptions
import os


class PrivNotes:
  MAX_NOTE_LEN = 2048;

  def __init__(self, password, data = None, checksum = None):
    """Constructor.
    
    Args:
      password (str) : password for accessing the notes
      data (str) [Optional] : a hex-encoded serialized representation to load
                              (defaults to None, which initializes an empty notes database)
      checksum (str) [Optional] : a hex-encoded checksum used to protect the data against
                                  possible rollback attacks (defaults to None, in which
                                  case, no rollback protection is guaranteed)

    Raises:
      ValueError : malformed serialized format
    """
    if data is None:
      self.kvs = {}

      #make src key
      self.salt = os.urandom(16)
      kdf = PBKDF2HMAC(algorithm = hashes.SHA256(), length = 32, salt = self.salt, iterations = 2000000)
      self.src_key = kdf.derive(bytes(password, 'ascii'))

      #make encryption key for notes and hash key for titles
      hash_key_gen = hmac.HMAC(self.src_key, hashes.SHA256())
      hash_key_gen.update(b"000")
      hash_key_gen_copy = hash_key_gen.copy()
      self.enc_key = hash_key_gen_copy.finalize()
      self.gcm = AESGCM(self.enc_key)
      self.nonce = int.from_bytes(self.salt, "big")

      hash_key_gen.update(b"001")
      hash_key_gen_copy1 = hash_key_gen.copy()
      self.hash_key = hash_key_gen_copy1.finalize()
      self.title_hash = hmac.HMAC(self.hash_key, hashes.SHA256())

      self.query_ok = True
      

    elif data is not None:
      if checksum is None:
        self.query_ok = False
        raise ValueError('malformed serialized format')

      self.kvs = pickle.loads(bytes.fromhex(data))
      #make src key
      first_dict_key  = list(self.kvs.keys())[0]
      self.salt = self.kvs[first_dict_key][2]

      kdf = PBKDF2HMAC(algorithm = hashes.SHA256(), length = 32, salt = self.salt, iterations = 2000000)
      self.src_key = kdf.derive(bytes(password, 'ascii'))

      #make encryption key for notes and hash key for titles
      hash_key_gen = hmac.HMAC(self.src_key, hashes.SHA256())
      hash_key_gen.update(b"000")
      hash_key_gen_copy = hash_key_gen.copy()
      self.enc_key = hash_key_gen_copy.finalize()
      self.gcm = AESGCM(self.enc_key)
      self.nonce = int.from_bytes(self.salt, "big")

      hash_key_gen.update(b"001")
      hash_key_gen_copy1 = hash_key_gen.copy()
      self.hash_key = hash_key_gen_copy1.finalize()

      self.title_hash = hmac.HMAC(self.hash_key, hashes.SHA256())

      hash_copy = self.title_hash.copy()
      hash_copy.update(bytes(pickle.dumps(self.kvs).hex(), 'ascii'))
      roll_prev = pickle.dumps(hash_copy.finalize()).hex()

      if checksum != roll_prev:
        self.query_ok = False
        raise ValueError('malformed serialized format')


      for title in self.kvs:
        try:
          self.gcm.decrypt(self.kvs[title][0].to_bytes(16, 'big'), self.kvs[title][1], title)
        except exceptions.InvalidTag:
          self.query_ok = False
          raise ValueError('malformed serialized format')
    
    self.query_ok = True
    

  def dump(self):
    """Computes a serialized representation of the notes database
       together with a checksum.
    
    Returns: 
      data (str) : a hex-encoded serialized representation of the contents of the notes
                   database (that can be passed to the constructor)
      checksum (str) : a hex-encoded checksum for the data used to protect
                       against rollback attacks (up to 32 characters in length)
    """
    if not self.query_ok:
      raise ValueError('need proper password')
    hash_copy = self.title_hash.copy()
    hash_copy.update(bytes(pickle.dumps(self.kvs).hex(), 'ascii'))
   
    checksum = hash_copy.finalize()
    return pickle.dumps(self.kvs).hex(), pickle.dumps(checksum).hex()

  def get(self, title):
    """Fetches the note associated with a title.
    
    Args:
      title (str) : the title to fetch
    
    Returns: 
      note (str) : the note associated with the requested title if
                       it exists and otherwise None
    """
    if not self.query_ok:
      raise ValueError('need proper password')

    hash_title = self.title_hash.copy()
    hash_title.update(bytes(title,"ascii"))
    check = hash_title.finalize()
    if check in self.kvs:
      ct = self.kvs[check][1]
      nonce = self.kvs[check][0].to_bytes(16, 'big')
      aad = check
      pt_padd = self.gcm.decrypt(nonce, ct, aad)
      plain_text = pt_padd.decode('UTF-8')
      plain_text = plain_text.replace('\00', '')
      return plain_text

    return None

  def set(self, title, note):                                               
    """Associates a note with a title and adds it to the database
       (or updates the associated note if the title is already
       present in the database).
       
       Args:
         title (str) : the title to set
         note (str) : the note associated with the title

       Returns:
         None

       Raises:
         ValueError : if note length exceeds the maximum
    """
    if not self.query_ok:
      raise ValueError('need proper password')

    if len(note) > self.MAX_NOTE_LEN:
      raise ValueError('Maximum note length exceeded')
    
    len_diff = self.MAX_NOTE_LEN - len(note)
    pad_note = note + '\00'*len_diff

    hash_title = self.title_hash.copy()
    hash_title.update(bytes(title, 'ascii'))
    check = hash_title.finalize()
    ct = self.gcm.encrypt(self.nonce.to_bytes(16, 'big'), bytes(pad_note, 'ascii'), check)   
    value = [self.nonce, ct, self.salt]  
    self.kvs[check] = value
    self.nonce = self.nonce + 1
    return None


  def remove(self, title):
    """Removes the note for the requested title from the database.
       
       Args:
         title (str) : the title to remove

       Returns:
         success (bool) : True if the title was removed and False if the title was
                          not found
    """

    if not self.query_ok:
      raise ValueError('need proper password')

    hash_title = self.title_hash.copy()
    hash_title.update(bytes(title,"ascii"))
    check = hash_title.finalize()
    if check in self.kvs:
      del self.kvs[check]
      return True

    return False
