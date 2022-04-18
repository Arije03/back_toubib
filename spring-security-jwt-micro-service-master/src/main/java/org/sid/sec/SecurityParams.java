package org.sid.sec;

public interface SecurityParams {
    public static final String JWT_HEADER_NAME="Authorization";
    public static final String SECRET="meriembenaicha80@gmail.com";
    public static final long EXPIRATION=10*240*3600;
    public static final String HEADER_PREFIX="Bearer ";
}
