package io.security.basicsecurity.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.security.basicsecurity.domain.AccountDto;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.thymeleaf.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// Json 방식 데이터 처리
public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {

    private ObjectMapper objectMapper = new ObjectMapper();
    protected AjaxLoginProcessingFilter(){
        super(new AntPathRequestMatcher("/api/login"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException {
        if(!isAjax(request)){
            throw new IllegalStateException("Authentication is not supported");
        }

        // Json 형식으로 들어온 데이터 객체로 저장
        AccountDto accountDto = objectMapper.readValue(request.getReader(), AccountDto.class);

        if(StringUtils.isEmpty(accountDto.getUserName()) || StringUtils.isEmpty(accountDto.getPassword())){
            throw new IllegalStateException("username or Password empty");
        }
        return null;
    }

    private boolean isAjax(HttpServletRequest request){

        if("XMLHttpRequest".equals(request.getHeader("X-Requested-with"))){
            return true;
        }

        return false;
    }
}
