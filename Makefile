NAME	= pamela.so

RM	= rm -rf

CC	= gcc

CHECK	:= `grep -rnw '/etc/pam.d/common-auth' -e 'auth optional pamela.so' | wc -l`

RULE	= 'echo "auth optional pamela.so" >> /etc/pam.d/common-auth'

RMRULE	= sed -i '/auth optional pamela.so/d' /etc/pam.d/common-auth

CHECK2	:= `grep -rnw '/etc/pam.d/common-password' -e 'password optional pamela.so' | wc -l`

RULE2	= 'echo "password optional pamela.so" >> /etc/pam.d/common-password'

RMRULE2	= sed -i '/password optional pamela.so/d' /etc/pam.d/common-password

CHECK3	:= `grep -rnw '/etc/pam.d/common-session' -e 'session optional pamela.so' | wc -l`

RULE3	= 'echo "session optional pamela.so" >> /etc/pam.d/common-session'

RMRULE3	= sed -i '/session optional pamela.so/d' /etc/pam.d/common-session

MKDIR	= mkdir -p

SRC	= src/open.c \
	src/close.c \
	src/passwd.c \
	src/shared.c

SRCDIR	= src

OBJDIR	= obj

SECURITYDIR	= /lib/security

LUKSDIR	= /home/luks

OBJ	= $(SRC:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

CFLAGS	= -Iinclude -fPIC -W -Wextra -Wall -Werror

LDFLAGS	= -lcryptsetup

$(NAME) : $(OBJ)

$(OBJ) : $(OBJDIR)/%.o : $(SRCDIR)/%.c
	@$(MKDIR) $(OBJDIR)
	@$(CC) $(CFLAGS) -c $< -o $@
	@echo "Compiled "$<" successfully !"

test:
	@echo "Tests complete !"

check:
	@if [ ! -f $(SECURITYDIR)/$(NAME) ]; then \
		echo "Installation incomplete: please run 'make install'"; \
	else \
		if [ $(CHECK) -lt 1 -o $(CHECK2) -lt 1 -o $(CHECK3) -lt 1 ]; then \
			echo "Installation incompletes: please run 'make install'"; \
		else \
			echo "The project is installed !"; \
		fi \
	fi

install: $(NAME)
	@sudo $(MKDIR) $(SECURITYDIR)
	@sudo $(CC) $(LDFLAGS) -shared -o $(SECURITYDIR)/$(NAME) $(OBJ)
	@sudo $(MKDIR) $(LUKSDIR)
	@sudo chmod 666 $(LUKSDIR)
	@echo "Linking complete !"
	@sudo $(RMRULE)
	@sudo sh -c $(RULE)
	@sudo $(RMRULE2)
	@sudo sh -c $(RULE2)
	@sudo $(RMRULE3)
	@sudo sh -c $(RULE3)
	@echo "Installation complete !"

uninstall: clean
	@sudo $(RMRULE3)
	@sudo $(RMRULE)
	@sudo $(RMRULE2)
	@sudo $(RM) $(SECURITYDIR)/$(NAME)
	@sudo $(RM) $(SECURITYDIR)
	@if [ -d ${HOME}/secure_data-rw ]; then \
		sudo umount ${HOME}/secure_data-rw || /bin/true; \
		$(RM) ${HOME}/secure_data-rw; \
		sudo cryptsetup luksClose ${USER}; \
	fi
	@sudo $(RM) $(LUKSDIR)
	@echo "Uninstallion complete !"

clean:
	@$(RM) $(OBJ)
	@$(RM) $(OBJDIR)
	@echo "Cleanup complete !"

re: clean $(NAME)

.PHONY: clean install uninstall re
