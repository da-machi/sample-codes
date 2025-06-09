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
			String nStr = "tsC_RzeWj4WwkGEDb62qSLbOONz7CtDm8_18fAeNZn10Y6fctbrd7yZe_B08ajpdFOiI1mEfT6Aw_bVFrBAB66OjU6J1RUqiyuraQub5h2Swbmw_OBLurejrcs0ngTDIey7U27j5CisG5dziabCCxhInDJNf_IJ1ZEY1io5Dn14NVw1ONI4oYoP1QVj1rOsljA_oeabvLgQX2_lK4VOanBgW00kCq9qQBP8U33mTp-dh3OIng6cMvSTpLi1j4ufJK_XY2JcdNTYCDnX-vgAzSMIJAN2w_S4X0pgLkqGP2_YOugwYFOeKxhS0Pt7WMrh468brtwjEb2XI3fao54jPpQ";
			String eStr = "AQAB";
			String token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJGQ3FGZjFoQ21KdmkwbzVQeTNidVNwWXNNOVVjdVFzeWNBbW9hRWhiVXRBIn0.eyJleHAiOjE3NDk1MDUyMzksImlhdCI6MTc0OTUwNDkzOSwiYXV0aF90aW1lIjowLCJqdGkiOiI2ZDllYzBjMy05NmI1LTQ1ODAtOTU3ZS00NzY3YmIwMzBlMGYiLCJpc3MiOiJodHRwOi8vMTkyLjE2OC41Ni4yOjgwODEvcmVhbG1zL215cmVhbG0iLCJhdWQiOiJteS1jbGllbnQiLCJzdWIiOiI2ZmJkZTBiMS05NDYwLTRkYmUtYmYxNi00Mzg5MTBhMmNhN2IiLCJ0eXAiOiJJRCIsImF6cCI6Im15LWNsaWVudCIsInNlc3Npb25fc3RhdGUiOiJiMDNlMDVjOC03ZDlkLTQ1YTAtOGIyZi03ZTgxMDg1YmFmNmYiLCJhdF9oYXNoIjoiYUMxRjhPaXpoMUhKU2pKR0VyMmdHUSIsImFjciI6IjEiLCJzaWQiOiJiMDNlMDVjOC03ZDlkLTQ1YTAtOGIyZi03ZTgxMDg1YmFmNmYiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsIm5hbWUiOiJ0ZXN0IHRhcm8iLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJ0ZXN0dXNlciIsImdpdmVuX25hbWUiOiJ0ZXN0IiwiZmFtaWx5X25hbWUiOiJ0YXJvIiwiZW1haWwiOiJ0ZXN0QHRlc3QifQ.H_vNDr16JrQA5UB_8f8x0IHE54wwIUf8WuIBKxkpxJLAvM19i0J2YUYdjnfT9nVYeExIo8E8wyuwdeKZ6sYQ2g7edM21zMZv8amvtv7E2_9b3Q9XStppaidrB6HOEbB20EKTfdOPvzjWHp6KcIBQ-z61g0QM3T6ANcUdvIwPpAqL3yKqkh_u3uSG4PqVolrB5fyQLI1awCAByvw2Bgj5Aumrx-70jdAQtbO3bmy-Pg449GoSi3W1nLPy5tIjh_R2Cup14P1Y_vJWIFe9VlNyhQLoBYyZYcZH40yNu374klxwUspAuVJg-2Umkre8YCYse1ybzSLItnWHNWov6uyGNg";

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
