package com.coding404.jwt.security.config;

import java.util.Date;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator.Builder;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;

public class JWTService {
	
	private static String secretKey = "coding404";
	
	//토큰생성
	public static String createToken(String username) {
		//알고리즘생성
	 	Algorithm alg = Algorithm.HMAC256(secretKey);
	 	//만료시간
	 	long expire = System.currentTimeMillis() + 3600000; //1시간뒤
	 	//토큰생성
	 	Builder builder = JWT.create().withSubject(username) //주제
						 				.withIssuedAt(new Date()) //발행일
						 				.withExpiresAt(new Date(expire)) //만료시간
						 				.withIssuer("coding404") //발행자
						 				.withClaim("admin", "공개클레임 홍길동~"); //+공개클레임
	 				
	 	return builder.sign(alg); //객체생성		
	 				
	}
	
	//토큰의 유효성확인
	public static boolean validateToken(String token) throws JWTVerificationException {
		
		Algorithm alg = Algorithm.HMAC256(secretKey);
		
		JWTVerifier verifier = JWT.require(alg).build(); //token을 검증할 객체
				 
		verifier.verify(token); //토큰검사 - 만료기간 or 토큰위조 가 발생하면 throws 처리됩니다.
		
		return true; //검증성공시 true, 검증실패시 false
	}
	
	
	
	
	
	
	
	
	
	
}
