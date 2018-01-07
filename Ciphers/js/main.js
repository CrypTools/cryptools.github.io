const $ = new DisplayJS(window);

$.on(".hamburger", "click", e => {
    if ($.getProp(".menu").css.top != "0px") {
        $.css(".menu", "top", "0")
        $.css(".hamburger", "color", "black")
        $.html(".hamburger", "<i class=\"fa fa-times\" aria-hidden=\"true\"></i>")
    } else {
        $.css(".menu", "top", "-100vh")
        $.css(".hamburger", "color", "white")
        $.html(".hamburger", "<i class=\"fa fa-bars\" aria-hidden=\"true\"></i>")
    }
})
var cipher;
var key;

$.target(() => {
	cipher = $.single(".f").options[$.single(".f").selectedIndex].text
	key = $.single("input.key").value
	const rendered = core($.single(".in").innerHTML, cipher, key)
	$.html(".out", Array.isArray(rendered) ? rendered[0] : rendered)
})

function core(txt, ciph, key, enc=0) {
	switch (ciph) {
		case "AESCipher":
			return enc == 0 ? txt.Aesencrypt(key) : txt.Aesdecrypt(key)
			break;
		case "AffineCipher":
			return enc == 0 ? txt.Afencrypt(JSON.parse(key)[0], JSON.parse(key)[1]) : txt.Afdecrypt(JSON.parse(key)[0], JSON.parse(key)[1], JSON.parse(key)[2])
			break;
		case "ATBASHCipher":
			return enc == 0 ? txt.Atencrypt() : txt.Atdecrypt()
			break;
		case "BitShiftCipher":
			return enc == 0 ? txt.Biencrypt(key) : txt.Bidecrypt(key)
			break;
		case "CaesarCipher":
			return enc == 0 ? txt.Caencrypt(Number(key)) : txt.Cadecrypt(Number(key))
			break;
		case "RailfenceCipher":
			return enc == 0 ? txt.Raencrypt(Number(key) != 0 ? Number(key) : 3) : txt.Radecrypt(Number(key) != 0 ? Number(key) : 3)
			break;
		case "ROT13Cipher":
			return txt.rot13()
			break;
		case "VigenereCipher":
			return enc == 0 ? txt.Viencrypt(key) : txt.Videcrypt(key)
			break;
		case "XORCipher":
			return enc == 0 ? txt.XOencrypt(key) : txt.XOdecrypt(key)
			break;
		case "MD5":
			return txt.md5()
			break;
		case "SHA256":
			return txt.sha256()
			break;
		default:
			return "Error: invalid input!"
	}
}
