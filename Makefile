NAME	= pamela.so

RM	= rm -rf

CC	= gcc

LD	= ld -x --shared

CHECK	:= `grep -rnw '/etc/pam.d/login' -e 'session    optional   pamela.so' | wc -l`

RULE	= 'echo "session    optional   pamela.so" >> /etc/pam.d/login'

RMRULE	= sed -i '/session    optional   pamela.so/d' /etc/pam.d/login

MKDIR	= mkdir -p

SRC	= src/open.c \
	src/close.c

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
		if [ $(CHECK) -lt 1 ]; then \
			echo "Installation incompletes: please run 'make install'"; \
		else \
			echo "The project is installed !"; \
		fi \
	fi

install: $(NAME)
	@sudo $(MKDIR) $(SECURITYDIR)
	@sudo $(LD) -o $(SECURITYDIR)/$(NAME) $(OBJ) $(LDFLAGS)
	@sudo $(MKDIR) $(LUKSDIR)
	@echo "Linking complete !"
	@if [ ! -f ${HOME}/.encrypt ]; then \
		sudo dd if=/dev/urandom bs=10M count=1 of=$(LUKSDIR)/${USER}; \
		sudo chmod 600 $(LUKSDIR)/${USER}; \
		sudo chown -R ${USER} $(LUKSDIR)/${USER}; \
		touch .tmp; \
		echo 'YES' | sudo cryptsetup luksFormat $(LUKSDIR)/${USER} .tmp; \
		echo '' | sudo cryptsetup luksOpen $(LUKSDIR)/${USER} ${USER}; \
		$(RM) .tmp; \
		sudo mkfs.ext3 /dev/mapper/${USER}; \
		sudo cryptsetup luksClose ${USER}; \
		echo "Container created !"; \
	fi
	@sudo $(RMRULE)
	@sudo sh -c $(RULE)
	@echo "Installation complete !"

uninstall: clean
	@sudo $(RMRULE)
	@sudo $(RM) $(SECURITYDIR)/$(NAME)
	@sudo $(RM) $(SECURITYDIR)
	@if [ -f ${HOME}/secure_data-rw ]; then \
		sudo umount ${HOME}/secure_data-rw || /bin/true; \
	fi
	@sudo $(RM) $(LUKSDIR)
	@echo "Uninstallion complete !"

clean:
	@$(RM) $(OBJ)
	@$(RM) $(OBJDIR)
	@echo "Cleanup complete !"

re: clean $(NAME)

.PHONY: clean install uninstall re
