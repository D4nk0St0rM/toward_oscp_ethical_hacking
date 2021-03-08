#!/usr/bin/python

#### D4nk0St0rM
#### spread l0v3, share Kn0wl3dge

import badcharacters

chars = badcharacters.Chars()

# Define your bad characters
chars.badChars = ['0a', '0d']

# Get a list of all characters, excluding the ones you have marked above
allChars = chars.getCharsExceptBad()

# (optional) Print out some helpers
print "You are excluding the following characters : " + chars.getConvertedBadChars() + "\n"
print "Hex should equal the grid below\n"
print chars.getHexGrid()

# You should recognise this bit and just include your characters from above ........
codeBuffer = "A" * 2606 + "B" * 4 + allChars

