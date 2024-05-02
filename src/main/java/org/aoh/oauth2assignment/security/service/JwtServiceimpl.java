package org.aoh.oauth2assignment.security.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

@Service
@RequiredArgsConstructor
public class JwtServiceimpl implements JwtService {


    @Value("${SECRET_KEY}")
    private String SECRET_KEY;

    /**
     * Extracts the username from a JWT token.
     *
     * @param token the JWT token
     * @return the username extracted from the token
     */
    public String extractUsername(String token) {

        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Extracts a specific claim from a JWT token.
     *
     * @param token          the JWT token
     * @param claimsResolver function to resolve the claim from the token's claims
     * @param <T>            the type of the claim
     * @return the extracted claim
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Generates an authentication JWT token.
     *
     * @param userDetails the user details
     * @return a list containing the authentication JWT token and refresh token
     */
    public List<String> generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    /**
     * Generates a JWT token with custom claims.
     *
     * @param extraClaims   additional claims to include in the token
     * @param userDetails   the user details
     * @return a list containing the JWT token and refresh token
     */
    public List<String> generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return List.of(
                Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 10))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact(),refreshToken(userDetails));
    }

    /**
     * Generates a refresh JWT token.
     *
     * @param userDetails the user details
     * @return the refresh JWT token
     */
    public String refreshToken(UserDetails userDetails){
        return Jwts
                .builder()
                .setSubject(userDetails.getUsername())
                .claim("type", "refreshToken")
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+1000*60*20))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Validates if a JWT token is valid for a specific user.
     *
     * @param token        the JWT token to validate
     * @param userDetails the user details to validate against
     * @return true if the token is valid for the user, false otherwise
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
