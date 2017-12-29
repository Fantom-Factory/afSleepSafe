
internal class TestIdSequence : Test {
	
	Void testToBase64() {
		verifyEq(Base64.toB64(0), "0")
		verifyEq(Base64.toB64(1), "1")
		verifyEq(Base64.toB64(2), "2")
		verifyEq(Base64.toB64(3), "3")
		
		verifyEq(Base64.toB64(10), "A")
		verifyEq(Base64.toB64(11), "B")
		verifyEq(Base64.toB64(12), "C")

		verifyEq(Base64.toB64(64), "10")
		verifyEq(Base64.toB64(65), "11")
		verifyEq(Base64.toB64(66), "12")

		verifyEq(Base64.toB64(74), "1A")
		verifyEq(Base64.toB64(75), "1B")
		verifyEq(Base64.toB64(76), "1C")
				
		verifyEq(Base64.toB64(5293177106265578783), "4br98YWC9qV")
		
		verifyEq(Base64.toB64(Int.maxVal), "7__________")
	}

	Void testFromBase64() {
		verifyEq(Base64.fromB64("0"), 0)
		verifyEq(Base64.fromB64("1"), 1)
		verifyEq(Base64.fromB64("2"), 2)
		verifyEq(Base64.fromB64("3"), 3)
		
		verifyEq(Base64.fromB64("A"), 10)
		verifyEq(Base64.fromB64("B"), 11)
		verifyEq(Base64.fromB64("C"), 12)

		verifyEq(Base64.fromB64("10"), 64)
		verifyEq(Base64.fromB64("11"), 65)
		verifyEq(Base64.fromB64("12"), 66)

		verifyEq(Base64.fromB64("1A"), 74)
		verifyEq(Base64.fromB64("1B"), 75)
		verifyEq(Base64.fromB64("1C"), 76)
				
		verifyEq(Base64.fromB64("4br98YWC9qV"), 5293177106265578783)
		
		verifyEq(Base64.fromB64("7__________"), Int.maxVal)
	}
}
