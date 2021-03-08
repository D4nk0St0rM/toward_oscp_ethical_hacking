# Just set the bad chars then call getCharsExceptBad to return the list of all characters without the bad ones in.

class Chars(object):
	badChars = [];
	def getCharsExceptBad(self):
		bytes = self.getCharsList()
		return ''.join(bytes)

	def getCharsList(self):
		allCharacters = ""
		for x in range(1, 256):
			item = ('{:02x}'.format(x))
			if item not in self.badChars:
				allCharacters += item

		bytes = []
		for i in range(0, len(allCharacters), 2):
			bytes.append(chr(int(allCharacters[i:i + 2], 16)))

		return bytes

	def getHexGrid(self, strLength = 16):
		bytes = self.getCharsList()
		counter = 0
		output = ""
		for character in bytes:
			output += self.byteToHex(character) + " "
			counter += 1
			if counter >= strLength:
				output += "\n"
				counter = 0

		return output

	def byteToHex(self, byteStr):
		"""
        Convert a byte string to it's hex string representation e.g. for output.
        """
		return ''.join(["%02X " % ord(x) for x in byteStr]).strip()

	def getConvertedBadChars(self):
		output = ""
		for char in self.badChars:
			output += str(chr(int(char, 16))) + "  "

		return repr(output)
