CREATE TABLE user_tb (
    user_id                NUMBER PRIMARY KEY,
    username               VARCHAR2(50) UNIQUE,
    password_expiry_date   DATE NOT NULL,
    password_reset_date    DATE,
    emp_id                 VARCHAR2(50) NOT NULL,
    creation_date          DATE NOT NULL
);

--
-- XX_EMP_PWDS_tbl table creation script
--
CREATE TABLE xx_emp_pwds_ashutosh_tbl (
    pwd_id                 NUMBER PRIMARY KEY,
    start_date             DATE NOT NULL,
    end_date               DATE,
    user_id                NUMBER NOT NULL REFERENCES user_tb ( user_id ),
    password               VARCHAR2(50) NOT NULL,
    block_status           VARCHAR2(2),
    invalid_login_count    NUMBER,
    last_invalid_attempt date,
    creation_date          DATE NOT NULL,
    updation_date          DATE NOT NULL,
    error_msg              VARCHAR2(100)
);

--   create or replace procedure sys01 (sysdate date) as begin dbms_output.put_line(sysdate); end;
--   execute sys01(sysdate);

truncate table sysadmin;
CREATE TABLE sysadmin (
    user_name   VARCHAR2(100) UNIQUE,
    password    VARCHAR2(100)
);

INSERT INTO sysadmin VALUES (
    'sysadmin',
    'admin01ashutosh'
);

SELECT
    *
FROM
    sysadmin;

CREATE OR REPLACE PACKAGE pwd_api AS
    PROCEDURE new_user_acccount_proc (
        u_name     user_tb.username%TYPE,
        password   xx_emp_pwds_ashutosh_tbl.password%TYPE,
        emp_id     user_tb.emp_id%TYPE
    );

    PROCEDURE login_proc (
        u_name     user_tb.username%TYPE,
        password   xx_emp_pwds_ashutosh_tbl.password%TYPE
    );

    PROCEDURE change_pwd_proc (
        u_name             user_tb.username%TYPE,
        current_password   xx_emp_pwds_ashutosh_tbl.password%TYPE,
        new_password       xx_emp_pwds_ashutosh_tbl.password%TYPE
    );

    PROCEDURE password_reset_proc (
        u_name           user_tb.username%TYPE,
        new_password     xx_emp_pwds_ashutosh_tbl.password%TYPE,
        admin_username   user_tb.username%TYPE,
        admin_password   xx_emp_pwds_ashutosh_tbl.password%TYPE
    );

END pwd_api;
/

CREATE OR REPLACE PACKAGE BODY pwd_api AS

    FUNCTION check_pwd_length_func (
        password_string xx_emp_pwds_ashutosh_tbl.password%TYPE
    ) RETURN BOOLEAN IS
    BEGIN
        IF ( length(password_string) >= 8 ) THEN
            RETURN true;
        END IF;
        RETURN false;
    EXCEPTION
        WHEN OTHERS THEN
            dbms_output.put_line(sqlerrm);
    END;

    FUNCTION check_password_char_func (
        password_string xx_emp_pwds_ashutosh_tbl.password%TYPE
    ) RETURN BOOLEAN IS

        v_char       CHAR;
        char_cnt     NUMBER := 0;
        num_cnt      NUMBER := 0;
        splchr_cnt   NUMBER := 0;
    BEGIN
        FOR i IN 1..length(password_string) LOOP
            v_char := substr(password_string, i, 1);
            IF ( v_char BETWEEN 'a' AND 'z' ) OR ( v_char BETWEEN 'A' AND 'Z' ) THEN
                char_cnt := char_cnt + 1;
            ELSIF ( v_char BETWEEN '0' AND '9' ) THEN
                num_cnt := num_cnt + 1;
            ELSE
                splchr_cnt := splchr_cnt + 1;
            END IF;

        END LOOP;

        IF ( splchr_cnt > 0 ) THEN
            RETURN false;
        ELSIF ( num_cnt = 0 ) THEN
            RETURN false;
        ELSIF ( char_cnt = 0 ) THEN
            RETURN false;
        END IF;
        
--        IF ( length(trim(translate(password_string, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', ' '))) > 0 )
--        THEN
--            RETURN false;
--        ELSIF ( nvl(length(trim(translate(password_string, '0123456789', ' '))), 0) = 0 ) THEN
--            RETURN false;
--        ELSIF ( nvl(length(trim(translate(password_string, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', ' '))), 0) = 0 ) THEN
--            RETURN false;
--        END IF;

        RETURN true;
    EXCEPTION
        WHEN OTHERS THEN
            dbms_output.put_line(sqlerrm);
    END;

    PROCEDURE block_user_account_proc (
        u_name user_tb.username%TYPE
    ) IS
        counter   NUMBER;
        userid    NUMBER;
    BEGIN
        SELECT
            u.user_id
        INTO userid
        FROM
            user_tb u
        WHERE
            u.username = u_name;

        SELECT
            nvl(MAX(pwd.invalid_login_count), 0)
        INTO counter
        FROM
            xx_emp_pwds_ashutosh_tbl pwd
        WHERE
            pwd.user_id = userid;

        IF ( counter > 3 ) THEN
            dbms_output.put_line(u_name || ', your account is blocked. Please raise a request to administrator for resetting the password.'
            );
            FOR i IN (
                SELECT
                    *
                FROM
                    xx_emp_pwds_ashutosh_tbl pwd
                WHERE
                    pwd.user_id = userid
            ) LOOP UPDATE xx_emp_pwds_ashutosh_tbl
            SET
                block_status = 'Y'
            WHERE
                pwd_id = i.pwd_id;

            END LOOP;

        END IF;

    EXCEPTION
        WHEN OTHERS THEN
            dbms_output.put_line(sqlerrm);
    END;

    FUNCTION check_old_passwords_func (
        u_name            user_tb.username%TYPE,
        password_string   xx_emp_pwds_ashutosh_tbl.password%TYPE
    ) RETURN BOOLEAN IS

        CURSOR check_old_pass IS
        SELECT * FROM (
            SELECT
                pwd_tbl.password
            FROM
                user_tb,
                xx_emp_pwds_ashutosh_tbl pwd_tbl
            WHERE
                pwd_tbl.user_id = user_tb.user_id
                AND pwd_tbl.error_msg IS NULL
                AND user_tb.username = u_name
            order by pwd_tbl.pwd_id desc)
        WHERE
            ROWNUM <= 5;

    BEGIN
        FOR i IN check_old_pass LOOP IF ( i.password = password_string ) THEN
            RETURN true;
        END IF;
        END LOOP;

        RETURN false;
    EXCEPTION
        WHEN OTHERS THEN
            dbms_output.put_line(sqlerrm);
    END;

    FUNCTION check_pwd_expiry_func (
        u_name user_tb.username%TYPE
    ) RETURN BOOLEAN IS

        CURSOR check_pass IS
        SELECT
            user_tb.username,
            user_tb.password_expiry_date
        FROM
            user_tb,
            xx_emp_pwds_ashutosh_tbl pwd_tbl
        WHERE
            pwd_tbl.user_id = user_tb.user_id
            AND user_tb.username = u_name;

    BEGIN
        FOR i IN check_pass LOOP IF ( i.password_expiry_date = SYSDATE ) THEN
--            dbms_output.put_line(i.username || ', your password is expired. Please update the password');
            RETURN true;
        END IF;
        END LOOP;

        RETURN false;
    EXCEPTION
        WHEN OTHERS THEN
            dbms_output.put_line(sqlerrm);
    END;

    FUNCTION counter_reset_func (
        u_id user_tb.user_id%TYPE
    ) RETURN BOOLEAN IS
        invalid_attempt_time DATE;
    BEGIN
        SELECT
            last_invalid_attempt
        INTO invalid_attempt_time
        FROM
            xx_emp_pwds_ashutosh_tbl
        WHERE
            user_id = u_id
            AND invalid_login_count = 1;

        IF SYSDATE >= invalid_attempt_time + ( 180 / 1440 ) THEN
            RETURN true;
        END IF;
        RETURN false;
    EXCEPTION
        WHEN no_data_found then
            return false;
        WHEN OTHERS THEN
            dbms_output.put_line(sqlerrm);
    END;

    PROCEDURE new_user_acccount_proc (
        u_name     user_tb.username%TYPE,
        password   xx_emp_pwds_ashutosh_tbl.password%TYPE,
        emp_id     user_tb.emp_id%TYPE
    ) IS

        user_id                NUMBER;
        creation_date          DATE;
        password_expiry_date   DATE;
        cnt                    NUMBER;
        max_id                 NUMBER;
        pwd_id                 NUMBER;
        cnt_pwd                NUMBER;
        max_pwdid              NUMBER;
        short_pass EXCEPTION;
        PRAGMA exception_init ( short_pass, -20000 );
        invalid_pass EXCEPTION;
        PRAGMA exception_init ( invalid_pass, -20001 );
    BEGIN
        IF ( check_pwd_length_func(password) = false ) THEN
            RAISE short_pass;
        END IF;
        IF ( check_password_char_func(password) = false ) THEN
            RAISE invalid_pass;
        END IF;
        SELECT
            COUNT(user_id)
        INTO cnt
        FROM
            user_tb;

        SELECT
            nvl(MAX(user_id), 0)
        INTO max_id
        FROM
            user_tb;

        IF cnt = 0 THEN
            user_id := 1001;
        ELSE
            user_id := max_id + 1;
        END IF;

        creation_date := SYSDATE;
        password_expiry_date := add_months(SYSDATE, 2);
        INSERT INTO user_tb VALUES (
            user_id,
            u_name,
            password_expiry_date,
            NULL,
            emp_id,
            creation_date
        );

        SELECT
            COUNT(pwd_id)
        INTO cnt_pwd
        FROM
            xx_emp_pwds_ashutosh_tbl;

        SELECT
            nvl(MAX(pwd_id), 0)
        INTO max_pwdid
        FROM
            xx_emp_pwds_ashutosh_tbl;

        IF cnt = 0 THEN
            pwd_id := 1;
        ELSE
            pwd_id := max_pwdid + 1;
        END IF;

        INSERT INTO xx_emp_pwds_ashutosh_tbl VALUES (
            pwd_id,
            SYSDATE,
            NULL,
            user_id,
            password,
            NULL,
            NULL,
            NULL,
            creation_date,
            SYSDATE,
            NULL
        );

    EXCEPTION
        WHEN short_pass THEN
            dbms_output.put_line(sqlcode || ': Password is too short.');
        WHEN invalid_pass THEN
            dbms_output.put_line(sqlcode || ': Password must be alphanumeric or Password must contain atleast 1 number and character.'
            );
        WHEN OTHERS THEN
            dbms_output.put_line(sqlerrm);
    END;

    PROCEDURE login_proc (
        u_name     user_tb.username%TYPE,
        password   xx_emp_pwds_ashutosh_tbl.password%TYPE
    ) IS

        CURSOR check_user_pwd IS
        SELECT
            pwd_tbl.pwd_id,
            user_tb.username,
            pwd_tbl.password,
            pwd_tbl.end_date
        FROM
            user_tb,
            xx_emp_pwds_ashutosh_tbl pwd_tbl
        WHERE
            pwd_tbl.user_id = user_tb.user_id;

        flag              NUMBER := 0;
        pwd_id            NUMBER;
        max_pwdid         NUMBER;
        userid            NUMBER;
        invalid_cnt       NUMBER;
        max_invalid_cnt   NUMBER;
        block_user EXCEPTION;
        PRAGMA exception_init ( block_user, -20008 );
        pass_expired EXCEPTION;
        PRAGMA exception_init ( pass_expired, -20009 );
        block_sts         VARCHAR2(100);
    BEGIN
        IF check_pwd_expiry_func(u_name) = true THEN
            RAISE pass_expired;
        END IF;
        SELECT
            u.user_id
        INTO userid
        FROM
            user_tb u
        WHERE
            u.username = u_name;

        IF ( counter_reset_func(userid) = true ) THEN
            UPDATE xx_emp_pwds_ashutosh_tbl
            SET
                invalid_login_count = NULL,
                block_status = NULL
            WHERE
                user_id = userid;
        END IF;

        SELECT DISTINCT
            block_status
        INTO block_sts
        FROM
            xx_emp_pwds_ashutosh_tbl pwd
        WHERE
            pwd.user_id = userid;

        IF ( block_sts = 'Y' ) THEN
            RAISE block_user;
        END IF;
        SELECT
            nvl(MAX(pwd_id), 0)
        INTO max_pwdid
        FROM
            xx_emp_pwds_ashutosh_tbl;

        SELECT
            nvl(MAX(pwd.invalid_login_count), 0)
        INTO max_invalid_cnt
        FROM
            xx_emp_pwds_ashutosh_tbl pwd
        WHERE
            pwd.user_id = userid;

        invalid_cnt := max_invalid_cnt;
        pwd_id := max_pwdid + 1;
        FOR i IN check_user_pwd LOOP
            IF ( i.username = u_name AND i.password = password AND i.end_date IS NULL ) THEN
                dbms_output.put_line('Welcome '
                                     || i.username
                                     || '!');
                flag := 1;
                UPDATE xx_emp_pwds_ashutosh_tbl
                SET
                    invalid_login_count = NULL,
                    block_status = NULL
                WHERE
                    user_id = userid;

            END IF;

            EXIT WHEN flag = 1;
        END LOOP;

        IF flag = 0 THEN
            dbms_output.put_line('Please enter correct password');
            invalid_cnt := invalid_cnt + 1;
            INSERT INTO xx_emp_pwds_ashutosh_tbl VALUES (
                pwd_id,
                SYSDATE,
                SYSDATE,
                userid,
                password,
                NULL,
                invalid_cnt,
                systimestamp,
                systimestamp,
                systimestamp,
                'Incorrect password'
            );

        END IF;
        
-- to block the user for 3 invalid attempt

        block_user_account_proc(u_name);
    EXCEPTION
        WHEN no_data_found THEN
            dbms_output.put_line(sqlcode || ': User does not exist. Please enter correct user id and password.');
        WHEN block_user THEN
            dbms_output.put_line(sqlcode || ': User is blocked. Please contact the administrator.');
        WHEN pass_expired THEN
            dbms_output.put_line(sqlcode || ': Your password is expired please reset it.');
        WHEN OTHERS THEN
            dbms_output.put_line(sqlerrm);
    END;

    PROCEDURE change_pwd_proc (
        u_name             user_tb.username%TYPE,
        current_password   xx_emp_pwds_ashutosh_tbl.password%TYPE,
        new_password       xx_emp_pwds_ashutosh_tbl.password%TYPE
    ) IS

        CURSOR check_user_pwd IS
        SELECT
            user_tb.user_id,
            pwd_tbl.pwd_id,
            user_tb.username,
            pwd_tbl.password,
            pwd_tbl.start_date,
            pwd_tbl.creation_date,
            pwd_tbl.end_date
        FROM
            user_tb,
            xx_emp_pwds_ashutosh_tbl pwd_tbl
        WHERE
            pwd_tbl.user_id = user_tb.user_id;

        flag        NUMBER := 0;
        short_pass EXCEPTION;
        PRAGMA exception_init ( short_pass, -20000 );
        invalid_pass EXCEPTION;
        PRAGMA exception_init ( invalid_pass, -20001 );
        pwd_id      NUMBER;
        max_pwdid   NUMBER;
        old_pass EXCEPTION;
        PRAGMA exception_init ( old_pass, -20002 );
    BEGIN
        IF ( check_pwd_length_func(new_password) = false ) THEN
            RAISE short_pass;
        ELSIF ( check_password_char_func(new_password) = false ) THEN
            RAISE invalid_pass;
        ELSIF ( check_old_passwords_func(u_name, new_password) = true ) THEN
            RAISE old_pass;
        END IF;

        SELECT
            nvl(MAX(pwd_id), 0)
        INTO max_pwdid
        FROM
            xx_emp_pwds_ashutosh_tbl;

        pwd_id := max_pwdid + 1;
        FOR i IN check_user_pwd LOOP
            IF ( i.username = u_name AND i.password = current_password AND i.end_date IS NULL ) THEN
                UPDATE user_tb
                SET
                    password_reset_date = SYSDATE,
                    password_expiry_date = add_months(SYSDATE, 2)
                WHERE
                    user_id = i.user_id;

                UPDATE xx_emp_pwds_ashutosh_tbl
                SET
                    password = new_password,
                    updation_date = SYSDATE
                WHERE
                    pwd_id = i.pwd_id;
                
                UPDATE xx_emp_pwds_ashutosh_tbl
                SET
                    last_invalid_attempt = null
                WHERE
                    user_id = i.user_id;

                INSERT INTO xx_emp_pwds_ashutosh_tbl VALUES (
                    pwd_id,
                    i.start_date,
                    SYSDATE,
                    i.user_id,
                    current_password,
                    NULL,
                    NULL,
                    NULL,
                    i.creation_date,
                    SYSDATE,
                    NULL
                );

                dbms_output.put_line('Password updated.');
                flag := 1;
            END IF;

            EXIT WHEN flag = 1;
        END LOOP;

        IF flag = 0 THEN
            dbms_output.put_line('Please enter correct user id and password');
        END IF;
    EXCEPTION
        WHEN short_pass THEN
            dbms_output.put_line(sqlcode || ': Password is too short.');
        WHEN invalid_pass THEN
            dbms_output.put_line(sqlcode || ': Password must be alphanumeric or Password must contain atleast 1 number and character.'
            );
        WHEN old_pass THEN
            dbms_output.put_line(sqlcode || ': Please enter a new password.');
        WHEN OTHERS THEN
            dbms_output.put_line(sqlerrm);
    END;

    PROCEDURE password_reset_proc (
        u_name           user_tb.username%TYPE,
        new_password     xx_emp_pwds_ashutosh_tbl.password%TYPE,
        admin_username   user_tb.username%TYPE,
        admin_password   xx_emp_pwds_ashutosh_tbl.password%TYPE
    ) IS

        sysadmin_user_name   VARCHAR2(100);
        sysadmin_password    VARCHAR2(100);
        pwd_id               NUMBER;
        max_pwdid            NUMBER;
        userid               NUMBER;
    BEGIN
        SELECT
            user_id
        INTO userid
        FROM
            user_tb
        WHERE
            username = u_name;

        SELECT
            user_name,
            password
        INTO
            sysadmin_user_name,
            sysadmin_password
        FROM
            sysadmin;

        SELECT
            nvl(MAX(pwd_id), 0)
        INTO max_pwdid
        FROM
            xx_emp_pwds_ashutosh_tbl;

        pwd_id := max_pwdid + 1;
        IF ( admin_username = sysadmin_user_name AND admin_password = sysadmin_password ) THEN
            DELETE FROM xx_emp_pwds_ashutosh_tbl
            WHERE
                user_id = userid;

            INSERT INTO xx_emp_pwds_ashutosh_tbl VALUES (
                pwd_id,
                SYSDATE,
                NULL,
                userid,
                new_password,
                NULL,
                NULL,
                NULL,
                systimestamp,
                systimestamp,
                NULL
            );

        ELSE
            dbms_output.put_line('Credentials of sysadmin are incorrect.');
        END IF;

    EXCEPTION
        WHEN OTHERS THEN
            dbms_output.put_line(sqlerrm);
    END;

END pwd_api;
/

DELETE FROM user_tb;

TRUNCATE TABLE xx_emp_pwds_ashutosh_tbl;

--testing procedure new_user_acccount_proc

DECLARE
    e_id       NUMBER;
    username   VARCHAR2(100);
    pass       VARCHAR2(100);
BEGIN
    e_id := :e_id;
    username := :username;
    pass := :pass;
    pwd_api.new_user_acccount_proc(username, pass, e_id);
EXCEPTION
    WHEN OTHERS THEN
        dbms_output.put_line(sqlerrm);
END;
/

--testing procedure login_proc
set SERVEROUTPUT ON;
select * from user_tb;
select * from xx_emp_pwds_ashutosh_tbl;
select * from  user_tb, xx_emp_pwds_ashutosh_tbl pwd where user_tb.user_id = pwd.user_id;

DECLARE
    username   VARCHAR2(100);
    pass       VARCHAR2(100);
BEGIN
    username := :username;
    pass := :pass;
    pwd_api.login_proc(username, pass);
EXCEPTION
    WHEN OTHERS THEN
        dbms_output.put_line(sqlerrm);
END;
/

--testing procedure change_pwd_proc

DECLARE
    username   VARCHAR2(100);
    pass       VARCHAR2(100);
    new_pass   VARCHAR2(100);
BEGIN
    username := :username;
    pass := :pass;                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            
    new_pass := :new_pass;
    pwd_api.change_pwd_proc(username, pass, new_pass);
EXCEPTION
    WHEN OTHERS THEN
        dbms_output.put_line(sqlerrm);
END;
/

-- testing procedure PASSWORD_RESET_PROC 
select * from user_tb;
select * from xx_emp_pwds_ashutosh_tbl;
select * from  user_tb, xx_emp_pwds_ashutosh_tbl pwd where user_tb.user_id = pwd.user_id order by pwd.user_id;
select * from sysadmin;

DECLARE
    username   VARCHAR2(100);
    new_pass       VARCHAR2(100);
    admin_username   VARCHAR2(100);
    admin_pass       VARCHAR2(100);
BEGIN
    admin_username := :admin_username;
    admin_pass := :admin_pass;
    username := :username;
    new_pass := :new_pass;
    pwd_api.PASSWORD_RESET_PROC(username, new_pass, admin_username, admin_pass);
EXCEPTION
    WHEN OTHERS THEN
        dbms_output.put_line(sqlerrm);
END;
/

-----------------------------------------------------------------------------------------------------------
set SERVEROUTPUT on;
--Another logic for checking alphanumeric
DECLARE
    pass       VARCHAR2(100);
    v_char char;
    char_cnt number := 0;
    num_cnt number := 0;
    splchr_cnt number := 0;
BEGIN
    pass := :pass;
   for i in 1..length(pass)
   loop
    v_char := substr(pass, i, 1);
    if (v_char between 'a' and 'z') then
    char_cnt := char_cnt + 1;
    elsif (v_char between '0' and '9') then
    num_cnt := num_cnt + 1;
    else
    splchr_cnt := splchr_cnt + 1;
    end if;
    end loop;
    if (splchr_cnt > 0) then
        dbms_output.put_line('Plese enter a alphanumeric password.');
    elsif (num_cnt = 0) then
        dbms_output.put_line('Password must contain atleast 1 number.');
    elsif (char_cnt = 0) then
         dbms_output.put_line('Password must contain atleast 1 alphabet.');
    else dbms_output.put_line('Thanks for entering a valid password.');
    end if;
EXCEPTION
    WHEN OTHERS THEN
        dbms_output.put_line(sqlerrm);
END;
/

drop table user_tb;
drop table user_tb;

select * from user_tb;
select * from xx_emp_pwds_ashutosh_tbl;
select * from  user_tb, xx_emp_pwds_ashutosh_tbl pwd where user_tb.user_id = pwd.user_id order by 1;
select user from dual;