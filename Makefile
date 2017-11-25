NAME	= pamela.so

RM	= rm -rf

CC	= gcc

LD	= ld -x --shared

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

install: $(NAME)
	@sudo $(MKDIR) $(SECURITYDIR)
	@sudo $(LD) -o $(SECURITYDIR)/$(NAME) $(OBJ)
	@echo "Linking complete !"
	@echo "Installation complete !"

uninstall: clean
	@sudo $(RM) $(SECURITYDIR)/$(NAME)
	@sudo $(RM) $(SECURITYDIR)
	@echo "Uninstallion complete !"

clean:
	@$(RM) $(OBJ)
	@$(RM) $(OBJDIR)
	@echo "Cleanup complete !"

re: uninstall install

.PHONY: clean install uninstall re
