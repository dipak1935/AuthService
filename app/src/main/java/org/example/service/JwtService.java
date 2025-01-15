package org.example.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.function.Function;

@Service
public class JwtService {

    public static final String SECRET="6f60a91df7c8f272126324d2051eb8678dc0bacade043c00e36eeae04ae8db79";

    public String extractUsername(String token){

        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims,T> claimResolver){

        final Claims claims=extractAllClaims(token);

        return claimResolver.apply(claims);
    }

    private Claims extractAllClaims(String token){

        return Jwts
                .parser()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignKey(){

        byte[] keyBytes= Decoders.BASE64.decode(SECRET);

        return Keys.hmacShaKeyFor(keyBytes);
    }

}
