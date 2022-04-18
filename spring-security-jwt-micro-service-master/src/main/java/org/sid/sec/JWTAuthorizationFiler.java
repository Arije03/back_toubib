package org.sid.sec;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class JWTAuthorizationFiler extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

    	response.addHeader("Access-Control-Allow-Origin", "*"); //j'autorize ay requete jeya men ay domaine elle fih les page l serveur mteei
		response.addHeader("Access-Control-Allow-Headers","Origin,Accept,X-Requested-With,Content-Type,Access-Control-Request-Method,Access-Control-Request-Headers,authorization"); //yelzem l'entete elle bech tjini w eni chnaamlelha autorisation ykoun fiha hedha kol
		response.addHeader("Access-Control-Allow-Headers","Access-Control-Allow-Origin,Access-Control-Allow-Credentials,authorization"); //aandek (app angular) el ha9 ta9ra l valeur mtee l'entete autorisation
		response.addHeader("Access-Control-Allow-Methods","GET,POST,PUT,DELETE,PATCH");
		if(request.getMethod().equals("OPTIONS")) { //si une requette tetebaathli bel options ok meghir manchouf jwt 
			response.setStatus(HttpServletResponse.SC_OK);
		}
		String jwtToken =request.getHeader(SecurityParams.JWT_HEADER_NAME);
		if(jwtToken ==null|| !jwtToken.startsWith(SecurityParams.HEADER_PREFIX)) {
			filterChain.doFilter(request, response);
			return ;
		
		}
		else {
			//vérifier signature elle hya tetkawen men header w payload w secret
			JWTVerifier verifier =JWT.require(Algorithm.HMAC256(SecurityParams.SECRET)).build();
			String jwt= jwtToken.substring(SecurityParams.HEADER_PREFIX.length());
			DecodedJWT decodedJWT =verifier.verify(jwt);
			String username=decodedJWT.getSubject();
			List<String> roles=decodedJWT.getClaims().get("roles").asList(String.class);
			Collection<GrantedAuthority>authorities =new ArrayList<>();	
			roles.forEach(rn ->{
				authorities.add(new SimpleGrantedAuthority(rn));
			});
			UsernamePasswordAuthenticationToken user=new UsernamePasswordAuthenticationToken(username,null,authorities);
			SecurityContextHolder.getContext().setAuthentication(user);
			filterChain.doFilter(request, response);
		}
    }
}
