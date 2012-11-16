GestPYPay
=========
***

## Overview

GestPYPay is an implementation in Python of GestPayCrypt italian bank **Banca Sella** Java classes. It allows to connect to online credit card payment **GestPay**.

This library is the conversion of the PHP GestPayCrypt and GestPayCryptHS by Alessandro Astarita.

His project is available at <http://gestpaycryptphp.sourceforge.net/>

For more information about GestPay, visit [Easynolo website](http://www.easynolo.it)


## Usage

The following code will explain a basic library usage, as per [Easynolo PHP example](http://service.easynolo.it/script/Php.html).

### Preparing a payment form:

	import gestpypay
	
	shopLogin = '9000001'	#Change with your shop login id
	currency = '242'	#242 is for EUR
	amount = '1.0'	#the amount to be paid - use dot for decimal digits
	transactionId = "YOURORD00001"	#the transaction id in your application
	customParameters = ""	#e.g. 'MY_CUSTOM_PARAM1=A_VALUE'
	
	sellaPaymentHandler = gestpypay.GestPayCrypt()
	
	sellaPaymentHandler.Debug = True
	sellaPaymentHandler.ProtocolAuthServer = 'https'
	sellaPaymentHandler.DomainName = 'testecomm.sella.it'

	sellaPaymentHandler.SetShopLogin(shopLogin)
	sellaPaymentHandler.SetCurrency(currency)
	sellaPaymentHandler.SetAmount(amount)
	sellaPaymentHandler.SetShopTransactionID(transactionId)
	
	sellaPaymentHandler.SetCustomInfo(customParameters)

	if sellaPaymentHandler.Encrypt():
		checkoutActionUrl = "%s://%s/gestpay/pagam.asp" % (sellaPaymentHandler.ProtocolAuthServer, sellaPaymentHandler.DomainName)
		shopLogin = sellaPaymentHandler.GetShopLogin()
		encryptedString = sellaPaymentHandler.GetEncryptedString()
	else:
		print sellaPaymentHandler.GetErrorCode()
		print sellaPaymentHandler.GetErrorDescription()

And then, in your rendered form (e.g. using Django):

	<form method="post" action="{{checkoutActionUrl}}">
		<input name="a" type="hidden" value="{{shopLogin}}" />
		<input name="b" type="hidden" value="{{encryptedString}}" />
		<input type="submit" value="Proceed with payment" name="submit" />
	</form>


You will, of course, follow the rest of the standard procedure, as described in the "GestPay - Specifiche tecniche sicurezza con crittografia" document.

***

####GestPyPay 1.0

&copy; 2012 Gianfranco Reppucci

[@giefferre](http://www.twitter.com/giefferre)

<gianfranco@gdlabs.it>