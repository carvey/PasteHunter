/*
rule crypto_address {

	meta:
		author = "@carvey"
	
	strings:
		//$btc_addr = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ nocase ascii wide
		//$btc_uri = /bitcoin:([13][a-km-zA-HJ-NP-Z1-9]{25,34})/ nocase ascii wide
		//$btc_xpub_key = /(xpub[a-km-zA-HJ-NP-Z1-9]{100,108})(\\?c=\\d*&h=bip\\d{2,3})?/ nocase ascii wide
		//$monero_addr = /(?:^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$)/ nocase ascii wide
		//$etherum_addr = /(?:^0x[a-fA-F0-9]{40}$)/ nocase asscii wide
		//$litecoin_addr = /(?:^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$)/ nocase ascii wide
		//$btc_cash_addr = /(?:^[13][a-km-zA-HJ-NP-Z1-9]{33}$)/ nocase ascii wide
		//$dash_addr = /(?:^X[1-9A-HJ-NP-Za-km-z]{33}$)/ nocase ascii wide
		//$ripple_addr = /(?:^r[0-9a-zA-Z]{33}$)/ nocase ascii wide
		//$neo_addr = /(?:^A[0-9a-zA-Z]{33}$)/ nocase ascii wide
		//$dogecoin_addr = /(?:^D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}$)/ nocase ascii wide

	condition:
		any of them
}
*/
