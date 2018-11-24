package rsa

import scala.annotation.tailrec
import scala.util.Random

object Main {

  def main(args: Array[String]): Unit = {
    val (publicKey, privateKey) = RSA.generateKey(512)
    println("Public Key: ")
    println(s"n: ${publicKey._1}")
    println(s"e: ${publicKey._2}")

    println()
    println("Private Key: ")
    println(s"d: ${privateKey._2}")


    val m = 150
    val enc = RSA.encrypt(m, publicKey)
    val dec = RSA.decrypt(enc, privateKey)
    println(s"msg: $m")
    println(s"enc: $enc")
    println(s"dec: $dec")
  }

}

object RSA {
  type PublicKey = (BigInt, BigInt)
  type PrivateKey = (BigInt, BigInt)

  def encrypt(m: BigInt, publicKey: PublicKey): BigInt = m.modPow(publicKey._2, publicKey._1)

  def decrypt(c: BigInt, privateKey: PrivateKey): BigInt = c.modPow(privateKey._2, privateKey._1)

  def generateKey(bitLength: Integer): (PublicKey, PrivateKey) = {
    val rnd = new Random()
    val p = BigInt.probablePrime(bitLength / 2, rnd)
    val q = BigInt.probablePrime(bitLength / 2, rnd)
    val n = p * q
    val Q = lcm(p - 1, q - 1)
    val e = randomE(Q, rnd)
    val d = e.modInverse(Q)

    val publicKey = (n, e)
    val privateKey = (n, d)
    (publicKey, privateKey)
  }

  @tailrec
  private def randomE(lcm: BigInt, rnd: Random): BigInt = {
    val e = BigInt(lcm.bitLength, rnd)
    if (e > 1 && e < lcm - 1 &&  areCoprime(e, lcm)) e
    else randomE(lcm, rnd)
  }

  def lcm(p: BigInt, q: BigInt): BigInt = p * q / p.gcd(q)

  def areCoprime(p: BigInt, q: BigInt): Boolean = p.gcd(q) == 1

}
