# coding=utf-8
'''
GestPYPay 1.0.0
(C) 2012 Gianfranco Reppucci <gianfranco@gdlabs.it>

	https://github.com/giefferre/gestpypay

GestPYPay is an implementation in Python of GestPayCrypt and
GestPayCryptHS italian bank Banca Sella Java classes. It allows to
connect to online credit card payment GestPay.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public License
version 2.1 as published by the Free Software Foundation.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details at 
http://www.gnu.org/copyleft/lgpl.html

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
'''

import urllib
import re
import requests


def empty(variable):
	if not variable:
		return True
	return False


class GestPayCrypt:

	# attributes
	ShopLogin			= None # Shop Login (e.g. Codice Esercente)
	Currency			= None # Currency code (242 = EUR)
	Amount				= None # Transaction Amount (e.g. 100.00)
	ShopTransactionID	= None # Merchant transaction id
	CardNumber			= None # Credit Card Number
	ExpMonth			= None # Credit Card Expiration Month
	ExpYear				= None # Credit Card Expiration Year
	BuyerName			= None # Client Name and Surname
	BuyerEmail			= None # Client Email Address
	Language			= None # Language
	CustomInfo			= None # Additional Informations
	AuthorizationCode	= None # Transaction Authorization Code
	ErrorCode			= None # Error code
	ErrorDescription	= None # Error description
	BankTransactionID	= None # GestPay transaction id
	AlertCode			= None # Alert code
	AlertDescription	= None # Alert description
	EncryptedString		= None # Crypted string
	ToBeEncript			= None # String to be encrypted
	Decrypted			= None # Decrypted string
	TransactionResult	= None # Transaction result
	ProtocolAuthServer	= None # 'http' or 'https'
	DomainName			= None # GetPay Domain
	separator			= None # Separator string for crypted string
	Version				= None
	Min					= None
	CVV					= None
	country				= None
	vbvrisp				= None
	vbv					= None


	# constructor
	def __init__(self, *args, **kwargs):
		self.ShopLogin = ""
		self.Currency = ""
		self.Amount = ""
		self.ShopTransactionID = ""
		self.CardNumber = ""
		self.ExpMonth = ""
		self.ExpYear = ""
		self.BuyerName = ""
		self.BuyerEmail = ""
		self.Language = ""
		self.CustomInfo = ""
		self.AuthorizationCode = ""
		self.ErrorCode = "0"
		self.ErrorDescription = ""
		self.BankTransactionID = ""
		self.AlertCode = ""
		self.AlertDescription = ""
		self.EncryptedString = ""
		self.ToBeEncrypt = ""
		self.Decrypted = ""
		self.ProtocolAuthServer = "http"
		self.DomainName = "ecomm.sella.it"
		self.ScriptEnCrypt = "/CryptHTTP/Encrypt.asp"
		self.ScriptDecrypt = "/CryptHTTP/Decrypt.asp"
		self.separator = "*P1*"
		self.Version = "1.0"
		self.Min = ""
		self.CVV = ""
		self.country = ""
		self.vbvrisp = ""
		self.vbv = ""
		self.debug = False

	# write methods
	
	def SetShopLogin(self, val):
		self.ShopLogin = val

	def SetCurrency(self, val):
		self.Currency = val

	def SetAmount(self, val):
		self.Amount = val

	def SetShopTransactionID(self, val):
		self.ShopTransactionID = urllib.quote_plus(val.strip())

	def SetCardNumber(self, val):
		self.CardNumber = val

	def SetExpMonth(self, val):
		self.ExpMonth = val

	def SetExpYear(self, val):
		self.ExpYear = val

	def SetMIN(self, val):
		self.Min = val

	def SetCVV(self, val):
		self.CVV = val

	def SetBuyerName(self, val):
		self.BuyerName = urllib.quote_plus(val.strip())

	def SetBuyerEmail(self, val):
		self.BuyerEmail = val.strip()

	def SetLanguage(self, val):
		self.Language = val.strip()

	def SetCustomInfo(self, val):
		self.CustomInfo = urllib.quote_plus(val.strip())

	def SetEncryptedString(self, val):
		self.EncryptedString = val


	# read only methods
	
	def GetShopLogin(self):
		return self.ShopLogin

	def GetCurrency(self):
		return self.Currency

	def GetAmount(self):
		return self.Amount

	def GetCountry(self):
		return self.country

	def GetVBV(self):
		return self.vbv

	def GetVBVrisp(self):
		return self.vbvrisp	
	
	def GetShopTransactionID(self):
		return urllib.unquote_plus(self.ShopTransactionID)

	def GetBuyerName(self):
		return urllib.unquote_plus(self.BuyerName)

	def GetBuyerEmail(self):
		return self.BuyerEmail

	def GetCustomInfo(self):
		return urllib.unquote_plus(self.CustomInfo)

	def GetAuthorizationCode(self):
		return self.AuthorizationCode

	def GetErrorCode(self):
		return self.ErrorCode

	def GetErrorDescription(self):
		return self.ErrorDescription

	def GetBankTransactionID(self):
		return self.BankTransactionID

	def GetTransactionResult(self):
		return self.TransactionResult

	def GetAlertCode(self):
		return self.AlertCode

	def GetAlertDescription(self):
		return self.AlertDescription

	def GetEncryptedString(self):
		return self.EncryptedString


	# encryption / decryption

	def Encrypt(self):
		err = ""
		self.ErrorCode = "0"
		self.ErrorDescription = ""
		self.ToBeEncrypt = ""

		if empty(self.ShopLogin):
			self.ErrorCode = "546"
			self.ErrorDescription = "IDshop not valid"
			return False

		if empty(self.Currency):
			self.ErrorCode = "552"
			self.ErrorDescription = "Currency not valid"
			return False

		if empty(self.Amount):
			self.ErrorCode = "553"
			self.ErrorDescription = "Amount not valid"
			return False

		if empty(self.ShopTransactionID):
			self.ErrorCode = "551"
			self.ErrorDescription = "Shop Transaction ID not valid"
			return False

		self.ToEncrypt(self.CVV, "PAY1_CVV")
		self.ToEncrypt(self.Min, "PAY1_MIN")
		self.ToEncrypt(self.Currency, "PAY1_UICCODE")
		self.ToEncrypt(self.Amount, "PAY1_AMOUNT")
		self.ToEncrypt(self.ShopTransactionID, "PAY1_SHOPTRANSACTIONID")
		self.ToEncrypt(self.CardNumber, "PAY1_CARDNUMBER")
		self.ToEncrypt(self.ExpMonth, "PAY1_EXPMONTH")
		self.ToEncrypt(self.ExpYear, "PAY1_EXPYEAR")
		self.ToEncrypt(self.BuyerName, "PAY1_CHNAME")
		self.ToEncrypt(self.BuyerEmail, "PAY1_CHEMAIL")
		self.ToEncrypt(self.Language, "PAY1_IDLANGUAGE")
		self.ToEncrypt(self.CustomInfo, "")

		self.ToBeEncrypt = self.ToBeEncrypt.replace(" ", "+")

		uri = self.ScriptEnCrypt + "?a=" + self.ShopLogin + "&b=" + self.ToBeEncrypt[len(self.separator):]
		full_url = self.ProtocolAuthServer + "://" + self.DomainName + uri
		
		if self.debug:
			print "URL richiesta: " + full_url + "\n"

		self.EncryptedString = self.HttpGetResponse(full_url, True)

		if self.EncryptedString == -1:
			return False

		if self.debug:
			print "Stringa criptata: " + self.EncryptedString + "\n"

		return True


	def Decrypt(self):
		err = ""
		self.ErrorCode = "0"
		self.ErrorDescription = ""
		
		if empty(self.ShopLogin):
			self.ErrorCode = "546"
			self.ErrorDescription = "IDshop not valid"
			return False

		if empty(self.EncryptedString):
			self.ErrorCode = "1009"
			self.ErrorDescription = "String to Decrypt not valid"
			return False
		
		uri = self.ScriptDecrypt + "?a=" + self.ShopLogin + "&b=" + self.EncryptedString
		full_url = self.ProtocolAuthServer + "://" + self.DomainName + uri

		if self.debug:
			print "URL richiesta: " + full_url + "\n"
		
		self.Decrypted = self.HttpGetResponse(full_url, False)

		if self.Decrypted == -1:
			return False

		elif empty(self.Decrypted):
			self.ErrorCode = "9999"
			self.ErrorDescription = "Empty decrypted string"
			return False

		self.Decrypted = self.Decrypted.replace("+", " ")

		if self.debug:
			print "Stringa decriptata: " + self.Decrypted + "\n"

		self.Parsing()

		return True


	# helpers

	def ToEncrypt(self, value, tagvalue):
		equal = "=" if tagvalue else ""

		if not empty(value):
			self.ToBeEncrypt += "%s%s%s%s" % (self.separator, tagvalue, equal, value)


	def HttpGetResponse(self, url, crypt):
		response = ""
		req = "crypt" if crypt else "decrypt"

		line = self.HttpGetLine(url)

		if line == -1:
			return -1

		if self.debug:
			print line

		reg = re.compile("#" + req + "string#([\w\W]*)#\/" + req + "string#").findall(line)
		err = re.compile("#error#([\w\W]*)#\/error#").findall(line)
		
		if self.debug:
			print url
			print req
			print line
			print reg
			print err
		
		if len(reg) > 0:
			response = reg[0].strip()

		elif len(err) > 0:
			err = err[0].split('-')

			if empty(err[0]) and empty(err[1]):
				self.ErrorCode = "9999"
				self.ErrorDescription = "Unknown error"

			else:
				self.ErrorCode = err[0].strip()
				self.ErrorDescription = err[1].strip()

			return -1

		else:
			self.ErrorCode = "9999"
			self.ErrorDescription = "Response from server not valid"
			return -1

		return response


	def HttpGetLine(self, url):
		try:
			r = requests.get(url)
		except Exception, e:
			print e
			self.ErrorCode = "9999"
			self.ErrorDescription = "Impossible to connect to host: " + host
			
			return -1

		output = ""

		for line in r.iter_lines():
			output = line
			break
		
		return output


	def Parsing(self):
		keyval = self.Decrypted.split(self.separator)
		
		for tagPAY1 in keyval:
			tagPAY1val = tagPAY1.split("=")
			
			if re.search("^PAY1_UICCODE", tagPAY1):
				self.Currency = tagPAY1val[1]

			elif re.search("^PAY1_AMOUNT", tagPAY1):
				self.Amount = tagPAY1val[1]

			elif re.search("^PAY1_SHOPTRANSACTIONID", tagPAY1):
				self.ShopTransactionID = tagPAY1val[1]
			
			elif re.search("^PAY1_CHNAME", tagPAY1):
				self.BuyerName = tagPAY1val[1]
			
			elif re.search("^PAY1_CHEMAIL", tagPAY1):
				self.BuyerEmail = tagPAY1val[1]
			
			elif re.search("^PAY1_AUTHORIZATIONCODE", tagPAY1):
				self.AuthorizationCode = tagPAY1val[1]
			
			elif re.search("^PAY1_ERRORCODE", tagPAY1):
				self.ErrorCode = tagPAY1val[1]
			
			elif re.search("^PAY1_ERRORDESCRIPTION", tagPAY1):
				self.ErrorDescription = tagPAY1val[1]
			
			elif re.search("^PAY1_BANKTRANSACTIONID", tagPAY1):
				self.BankTransactionID = tagPAY1val[1]
			
			elif re.search("^PAY1_ALERTCODE", tagPAY1):
				self.AlertCode = tagPAY1val[1]
			
			elif re.search("^PAY1_ALERTDESCRIPTION", tagPAY1):
				self.AlertDescription = tagPAY1val[1]
			
			elif re.search("^PAY1_CARDNUMBER", tagPAY1):
				self.CardNumber = tagPAY1val[1]
			
			elif re.search("^PAY1_EXPMONTH", tagPAY1):
				self.ExpMonth = tagPAY1val[1]
			
			elif re.search("^PAY1_EXPYEAR", tagPAY1):
				self.ExpYear = tagPAY1val[1]
			
			elif re.search("^PAY1_COUNTRY", tagPAY1):
				self.ExpYear = tagPAY1val[1]
			
			elif re.search("^PAY1_VBVRISP", tagPAY1):
				self.ExpYear = tagPAY1val[1]
			
			elif re.search("^PAY1_VBV", tagPAY1):
				self.ExpYear = tagPAY1val[1]
			
			elif re.search("^PAY1_IDLANGUAGE", tagPAY1):
				self.Language = tagPAY1val[1]
			
			elif re.search("^PAY1_TRANSACTIONRESULT", tagPAY1):
				self.TransactionResult = tagPAY1val[1]
			
			else:
				self.CustomInfo += tagPAY1 + self.separator

		self.CustomInfo = self.CustomInfo[:-len(self.separator)]



class GestPayCryptHS(GestPayCrypt):

	# constructor
	def __init__(self, *args, **kwargs):
		self.ShopLogin = ""
		self.Currency = ""
		self.Amount = ""
		self.ShopTransactionID = ""
		self.CardNumber = ""
		self.ExpMonth = ""
		self.ExpYear = ""
		self.BuyerName = ""
		self.BuyerEmail = ""
		self.Language = ""
		self.CustomInfo = ""
		self.AuthorizationCode = ""
		self.ErrorCode = "0"
		self.ErrorDescription = ""
		self.BankTransactionID = ""
		self.AlertCode = ""
		self.AlertDescription = ""
		self.EncryptedString = ""
		self.ToBeEncrypt = ""
		self.Decrypted = ""
		self.ProtocolAuthServer = "https"
		self.DomainName = "ecomm.sella.it"
		self.ScriptEnCrypt = "/CryptHTTPS/Encrypt.asp"
		self.ScriptDecrypt = "/CryptHTTPS/Decrypt.asp"
		self.separator = "*P1*"
		self.Version = "1.0"
		self.Min = ""
		self.CVV = ""
		self.country = ""
		self.vbvrisp = ""
		self.vbv = ""
		self.debug = False