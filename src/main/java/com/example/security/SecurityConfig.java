package com.example.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;


@Configuration
@EnableWebSecurity // 웹 보안 활성화
@Order(0) // 보안 폭이 좁은 것을 우선순위로 둔다
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    UserDetailsService userDetailsService;
    
    
    /**************************************
     *           정적파일 무조건 허용
     **************************************/
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations()) //기본 설정된 모든 정적파일들
                                  .antMatchers("/favicon.ico", "/resources/**", "/error");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        /**************************************
         *               인가 정책
         **************************************/
        http
            .antMatcher("/test1/**/")       // 해당 경로로 들어오는 요청만 인가심사
            .authorizeRequests()            // 요청에 대한 인가심사 시작 (위에서부터 아래로. 아래로 갈수록 권한이 넓어지도록 설정)
                .antMatchers("/test1/login").permitAll()
                .antMatchers("/test1/user").hasRole("USER")
                .antMatchers("/test1/admin/pay").hasRole("ADMIN")
                .antMatchers("/test1/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated()

        //  .antMatchers("/test/ip").hasIpAddress("127.0.0.1")
        //  .mvcMatchers(HttpMethod.GET, "shop/mvc").permitAll();
        ;



        /**************************************
         *               인증 정책
         **************************************/

        //------- form 로그인 사용 --------
        http
                .formLogin()
            //  .loginPage("/loginPage")            // 커스텀 로그인 페이지 url
                .defaultSuccessUrl("/test1")        // 로그인 성공시 이동할 url
                .failureForwardUrl("/login")  // 로그인 실패시 이동할 url
                .usernameParameter("username")      // 로그인 아이디 파라미터명
                .passwordParameter("password")      // 로그인 패스워드 파라미터명
                .loginProcessingUrl("/login_proc")  // 로그인 프로세싱 url (default = /login)
                // 로그인 성공시 실행되는 핸들러
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                        System.out.println("authentication " + authentication.getName());

                        RequestCache requestCache = new HttpSessionRequestCache();
                        SavedRequest request = requestCache.getRequest(httpServletRequest, httpServletResponse); // 원래 사용자가 가고자 했던 요청정보
                        String redirectUrl = request.getRedirectUrl();
                        httpServletResponse.sendRedirect(redirectUrl);
                    }
                })
                // 로그인 실패시 실행되는 핸들러
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
                        System.out.println("exception " + e.getMessage());
                        httpServletResponse.sendRedirect("/login");
                    }
                })
        ;


        //------- rememberMe 사용 (세션이 없어도 로그인상태 유지) --------
        http
                .rememberMe()
                .rememberMeParameter("remember-me")       // 파라미터명 (default = remember-me)
                .tokenValiditySeconds(3600)               // 유효기간 (default = 14일)
                .alwaysRemember(false)                    // 체크하지 않아도 항상 실행 (default = false)
                .userDetailsService(userDetailsService)   // 사용자 계정 조회 처리 (반드시 등록해주기)
        ;



        //------- 세션관리 --------
        http
                .sessionManagement()
                .maximumSessions(1)              // 최대 세션 허용개수
                .maxSessionsPreventsLogin(true)  // 현재 사용자 인증 실패 처리
            //  .maxSessionsPreventsLogin(false) // 이전 사용자 세션 만료
        ;



        //------- 로그아웃 사용 --------
        http
                .logout()
                .logoutSuccessUrl("/logout")  // 로그아웃 url
                .logoutSuccessUrl("/login")   // 로그아웃 성공시 이동하는 url
                .deleteCookies("remember-me") // 쿠키 삭제
                // 로그아웃 처리 핸들러
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) {
                        HttpSession session = httpServletRequest.getSession();
                        session.invalidate();
                    }
                })
                // 로그아웃 성공시 실행되는 핸들러
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                        httpServletResponse.sendRedirect("/login");
                    }
                })
        ;



        /**************************************
         *              예외 공용 처리
         **************************************/

        //------- 인가 예외 처리 : 권한이 없는 url 접속 --------
        http
                .exceptionHandling()
                .accessDeniedHandler(new AccessDeniedHandler() {
                    @Override
                    public void handle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AccessDeniedException e) throws IOException, ServletException {
                        httpServletResponse.sendRedirect("/test1/denied");
                    }
                })
        ;

        //------- 인증 예외 처리 : spring security login 페이지가 비활성화 된다 -> 커스텀 loginPage를 생성해야함--------
        /*
         http
                .exceptionHandling()
                .authenticationEntryPoint(new AuthenticationEntryPoint() {
                    @Override
                    public void commence(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
                        httpServletResponse.sendRedirect("/login");
                    }
                })

        ;
         */


        /**************************************
         *              csrf 해제 (테스트)
         **************************************/
        // get을 제외한 요청 시 csrf filter가 생성한 토큰을 실어보내지 않으면 요청이 실패된다
        http
                .csrf().disable();
    }
}


/********************************
 * 다중 보안설정 (넓은 권한일수록 Order 높게주기)
 ********************************/
@Configuration
@Order(1)
class SecurityConfig2 extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                .authorizeRequests()
                .anyRequest().permitAll()
                .and()
                .formLogin()
        ;
    }
}
