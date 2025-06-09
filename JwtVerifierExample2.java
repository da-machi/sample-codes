package sample;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.time.Instant;
import java.util.Base64;

import org.json.JSONObject;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
//...（import文やbase64UrlToBigInt()などはそのまま）

public class JwtVerifierExample2 {


	// Base64URLデコード（Java標準のBase64のURL版で）
	public static BigInteger base64UrlToBigInt(String base64Url) {
		String base64 = base64Url.replace('-', '+').replace('_', '/');
		int padding = (4 - base64.length() % 4) % 4;
		base64 += "=".repeat(padding);
		byte[] decoded = Base64.getDecoder().decode(base64);
		return new BigInteger(1, decoded);
	}

	public static void main(String[] args) {
		try {
			String nStr = "aaaaaaaaaaaaaaaaaaaaaaaaaa";
			String eStr = "AAAA";
			String token = "aaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbb.cccccccccccccccccccccccccccccc";

			BigInteger n = base64UrlToBigInt(nStr);
			BigInteger e = base64UrlToBigInt(eStr);

			RSAPublicKeySpec spec = new RSAPublicKeySpec(n, e);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			RSAPublicKey publicKey = (RSAPublicKey) kf.generatePublic(spec);

			Algorithm algorithm = Algorithm.RSA256(publicKey, null);
			JWTVerifier verifier = JWT.require(algorithm)
					.withAudience("my-client")
					.withIssuer("http://192.168.56.2:8081/realms/myrealm")
					.build();

			DecodedJWT jwt = verifier.verify(token);

			System.out.println("署名検証成功！");

			// --- alg 検証（署名アルゴリズム） ---
			String headerJsonStr = new String(Base64.getUrlDecoder().decode(jwt.getHeader()));
			JSONObject header = new JSONObject(headerJsonStr);
			String alg = header.getString("alg");
			if (!"RS256".equals(alg)) {
				throw new JWTVerificationException("Unsupported algorithm: " + alg);
			}

			// --- iat/exp 検証 ---(TODO: チェック、これってライブラリでやってるんじゃね？)
			long nowEpoch = Instant.now().getEpochSecond();

			Long iat = jwt.getIssuedAt().toInstant().getEpochSecond();
			// 発行時刻（iat）が現在時刻よりも未来すぎる場合は不正と見なす
			// 通常、発行時刻は現在時刻以前であるべき。ただし最大60秒のクロックずれを許容
			if (iat > nowEpoch + 60) {
				throw new JWTVerificationException("iat is too far in the future: " + iat);
			}

			Long exp = jwt.getExpiresAt().toInstant().getEpochSecond();
			// 有効期限（exp）がすでに現在時刻を過ぎていればトークンは無効とする
			// クロックずれや微小な遅延を考慮して、最大60秒まで過去を許容
			if (exp < nowEpoch - 60) {
				throw new JWTVerificationException("Token expired at: " + exp);
			}

			// --- ペイロード整形出力 ---
			String payloadJsonStr = new String(Base64.getUrlDecoder().decode(jwt.getPayload()));
			JSONObject payload = new JSONObject(payloadJsonStr);

			System.out.println("ヘッダー（整形）:\n" + header.toString(4));
			System.out.println("ペイロード（整形）:\n" + payload.toString(4));

		} catch (JWTVerificationException e) {
			System.err.println("署名検証失敗（JWT検証エラー）: " + e.getMessage());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
