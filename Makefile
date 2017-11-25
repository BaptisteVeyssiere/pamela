NAME	= pamela.so

RM	= rm -rf

CC	= gcc

LD	= ld -x --shared

CHECK	:= `grep -rnw '/etc/pam.d/login' -e 'session    optional   pamela.so' | wc -l`

RULE	= 'echo "session    optional   pamela.so" >> /etc/pam.d/login'

RMRULE	= sed -i '/session    optional   pamela.so/d' /etc/pam.d/login

MKDIR	= mkdir -p

SRC	= src/pamela.c

SRCDIR	= src

OBJDIR	= obj

SECURITYDIR	= /lib/security

OBJ	= $(SRC:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

CFLAGS	= -Iinclude -fPIC -W -Wextra -Wall -Werror

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
		if [ $(CHECK) -lt 1 ]; then \
			echo "Installation incompletes: please run 'make install'"; \
		else \
			echo "The project is installed !"; \
		fi \
	fi

install: $(NAME)
	@sudo $(MKDIR) $(SECURITYDIR)
	@sudo $(LD) -o $(SECURITYDIR)/$(NAME) $(OBJ)
	@echo "Linking complete !"
	@sudo $(RMRULE)
	@sudo sh -c $(RULE)
	@echo "Installation complete !"

uninstall: clean
	@sudo $(RMRULE)
	@sudo $(RM) $(SECURITYDIR)/$(NAME)
	@sudo $(RM) $(SECURITYDIR)
	@echo "Uninstallion complete !"

clean:
	@$(RM) $(OBJ)
	@$(RM) $(OBJDIR)
	@echo "Cleanup complete !"

re: uninstall install

.PHONY: clean install uninstall re
