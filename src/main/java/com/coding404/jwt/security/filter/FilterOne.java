package com.coding404.jwt.security.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class FilterOne implements Filter {

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		
		System.out.println("=========filter one 실행됨=======>");
		
		
		HttpServletRequest req = (HttpServletRequest)request;
		HttpServletResponse res = (HttpServletResponse) response;
		
		//토큰검사 
		String token = req.getHeader("Authorization");

		if(token != null && token.equals("token") ) { //테스트용도의 토큰
			
			chain.doFilter(request, response); //다음 필터로의 연결
			
		} else { //토큰이 없는경우
			res.setCharacterEncoding("utf-8");
			res.setContentType("text/plain");
			res.sendError(403, "토큰없음");
		}
		
		//chain.doFilter(request, response); //다음 필터로의 연결
		
	}

}
