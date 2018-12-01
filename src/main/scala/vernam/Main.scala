package vernam

import scala.annotation.tailrec
import scala.io.Source
import scala.util.Random

object Main {

  def main(args: Array[String]): Unit = {
    val startTime = System.currentTimeMillis()

    val message = Source.fromResource("vernam/message_in").getLines.mkString("\n")
    val byteMessage = BigInt(message.getBytes)
    println(s"Original message: $message")
    println(s"Original message bit length: ${byteMessage.bitLength} \n")

    val key = BlumBlumShubGenerator.generateKey(byteMessage.bitLength, 512)
    println(s"Key: ${key.toString(2)}")
    println(s"Key bit length: ${key.bitLength}")
    val enc = byteMessage ^ key
    println(s"Enc: ${enc.toString(2)} \n")

    val dec = key ^ enc
    println(s"Decrypted message: ${new String(dec.toByteArray)} \n")

    val endTime = System.currentTimeMillis()
    println(s"Elapsed time: ${endTime - startTime}ms")
  }

}

object BlumBlumShubGenerator {
  def generateKey(bitLength: Int, pqBitLength: Int): BigInt = {
    val rnd = new Random()
    val p = randomPrime(pqBitLength, rnd)
    val q = randomPrime(pqBitLength, rnd)
    val n = p * q
    val seed = generateSeed(pqBitLength * 2, rnd, n)
    val x0 = seed.pow(2) mod n
    internalGenerateKey(bitLength, 0, x0, n, BigInt(bitLength, new Random()))
  }

  @tailrec
  private def randomPrime(bitLength: Int, rnd: Random): BigInt = {
    val p = BigInt.probablePrime(bitLength, rnd)
    if (p.mod(4) == 3) p
    else randomPrime(bitLength, rnd)
  }

  @tailrec
  private def generateSeed(bitLength: Int, rnd: Random, n: BigInt): BigInt = {
    val seed = BigInt(bitLength, rnd)
    // Wystarczy, że ziarno będzie większe, większe bądź równe?
    if (areCoprime(n, seed) && seed > 1 && seed < n - 1) seed
    else generateSeed(bitLength, rnd, n)
  }

  @tailrec
  private def internalGenerateKey(bitLength: Int, ctr: Int, prevX: BigInt, n: BigInt, key: BigInt): BigInt = {
    if (ctr == bitLength) key
    else {
      val x = prevX.pow(2) mod n
      val k = x mod 2

      if (k == 1) internalGenerateKey(bitLength, ctr + 1, x, n, key.setBit(ctr))
      else internalGenerateKey(bitLength, ctr + 1, x, n, key.clearBit(ctr))
    }
  }

  private def areCoprime(p: BigInt, q: BigInt): Boolean = p.gcd(q) == 1

}
