package rsa

import java.io.File
import java.nio.file.Files

import javax.imageio.ImageIO
import rsa.RSA.{PrivateKey, PublicKey}

import scala.annotation.tailrec
import scala.util.Random

object Main {

  def main(args: Array[String]): Unit = {

    /**
      * Deleting existing output file
      * Creating new output file by copying original image
      */
    val inputFilePath = "src/main/resources/rsa/tropic.jpg"
    val outputDecFilePath = "src/main/resources/rsa/tropic_out_dec.jpg"

    val inputFile = new File(inputFilePath)
    val outputFileDec = new File(outputDecFilePath)

    if (outputFileDec.exists()) outputFileDec.delete()

    Files.copy(inputFile.toPath, outputFileDec.toPath)

    val img = ImageIO.read(inputFile)
    val outputImgDec = ImageIO.read(outputFileDec)
    println(s"img size: ${img.getWidth} x ${img.getHeight}")


    /**
      * Processing image by generating key, encrypting every pixel
      * and storing it in Sequence of tuples consisting encrypted pixel and it's (x,y) position in image
      * Finally processing every encrypted pixel by decrypting it and writing content to output file
      */
    import Utilities._
    println("Generating RSA keys...")
    val (publicKey, privateKey) = RSA.generateKey(512)
    println(prettyRsaKeysData(publicKey, privateKey))

    println("Processing image...")
    val encPixels = for {
      width <- Range(0, img.getWidth)
      height <- Range(0, img.getHeight)
    } yield {
      val m = img.getRGB(width, height)
      val enc = RSA.encrypt(-m, publicKey)
      (enc, width, height)
    }

    encPixels.foreach {
      case (pixel: BigInt, x: Int, y: Int) =>
        val decPixel = RSA.decrypt(pixel, privateKey)
        outputImgDec.setRGB(x, y, -decPixel.toInt)
    }

    println("Writing decripted image to output file...")
    ImageIO.write(outputImgDec, "jpg", outputFileDec)
  }

}

/**
  * RSA key generator with encryption and decryption functions
  * with auxiliary methods
  */
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
    if (e > 1 && e < lcm - 1 && areCoprime(e, lcm)) e
    else randomE(lcm, rnd)
  }

  private def lcm(p: BigInt, q: BigInt): BigInt = p * q / p.gcd(q)

  private def areCoprime(p: BigInt, q: BigInt): Boolean = p.gcd(q) == 1

}

/**
  * Utilities providing diagnostic info to print to the console
  */
object Utilities {

  def prettyRsaKeysData(publicKey: PublicKey, privateKey: PrivateKey): String = {
    s"\n Public Key: \n n: ${publicKey._1} \n e: ${publicKey._2} \n\n Private Key: \n d: ${privateKey._2} \n"
  }

}
