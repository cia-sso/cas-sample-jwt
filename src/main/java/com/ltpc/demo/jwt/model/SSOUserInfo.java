package com.ltpc.demo.jwt.model;

import lombok.Getter;
import lombok.Setter;

/**
 * Created with IntelliJ IDEA.
 * User: liutong
 * Date: 2018/11/12
 * Time: 10:49 AM
 * Description:
 **/
@Getter
@Setter
public class SSOUserInfo {
    private Long subCustomerId;
    private String subCustomerame;
    private String loginName;
    private String email;
    private String telephone;
    private Long customerId;
    private Long accountId;
    private Long departmentId;
}
