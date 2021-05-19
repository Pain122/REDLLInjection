; read 2 numbers from input (from 0 to 255)
; print result


jmp BEGIN

READ_NUMBER proc
    push bp
    mov bp, sp
     
    xor cx, cx               
     
    READ_SYMBOL:
        mov ah, 01h
        int 21h 
        
        cmp al, 20h ; zf
        je END
        
        mov dl, al
        sub dl, 30h
        mov al, 10 
        mul cl
        mov cl, al  
        add cl, dl 
        
        jmp READ_SYMBOL  
        
    END: 
        pop bp
        ret
           
READ_NUMBER endp        
 
WRITE_NUMBER proc
    
    mov cl, 100
    div cl
    xor bx, bx
     
    mov bl, ah
    jmp PRINT 
    
  TEN:
    mov cl, 10
    mov ax, bx
    div cl
    jmp PRINT_TEN  
    
  PRINT:
    mov dl, al
    add dl, 30h
    mov ah, 02h
    int 21h 
    jmp TEN
  
  PRINT_TEN:
    mov cl, ah
    mov dl, al
    add dl, 30h
    mov ah, 02h
    int 21h 
    mov dl, cl
    add dl, 30h
    mov ah, 02h
    int 21h
    
                            
          
WRITE_NUMBER endp 

WRONG_INPUT:
ret
 
BEGIN:

call READ_NUMBER 
push cx
call READ_NUMBER
pop ax
add ax, cx
cmp ax, 1FEh  
jg  WRONG_INPUT 
call WRITE_NUMBER

