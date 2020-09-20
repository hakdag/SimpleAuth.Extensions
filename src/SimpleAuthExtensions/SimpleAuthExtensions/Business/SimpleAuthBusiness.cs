using SimpleAuthExtensions.Service;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace SimpleAuthExtensions.Business
{
    public class SimpleAuthBusiness : ISimpleAuthBusiness
    {
        private readonly IAuthenticationClient authenticationClient;
        private readonly ILockAccountClient lockAccountClient;
        private readonly IUnLockAccountClient unlockAccountClient;
        private readonly IChangePasswordClient changePasswordClient;
        private readonly IRolesClient rolesClient;
        private readonly IUserRoleClient userRoleClient;
        private readonly IUsersClient usersClient;
        private readonly IPermissionsClient permissionsClient;
        private readonly IRolePermissionClient rolePermissionClient;
        private readonly IUserPermissionClient userPermissionClient;
        private readonly IPasswordResetClient passwordResetClient;
        private readonly IGeneratePasswordResetKeyClient generatePasswordResetKeyClient;
        private readonly IValidatePasswordResetKeyClient validatePasswordResetKeyClient;

        public SimpleAuthBusiness(
            IAuthenticationClient authenticationClient,
            ILockAccountClient lockAccountClient,
            IUnLockAccountClient unlockAccountClient,
            IChangePasswordClient changePasswordClient,
            IRolesClient rolesClient,
            IUserRoleClient userRoleClient,
            IUsersClient usersClient,
            IPermissionsClient permissionsClient,
            IRolePermissionClient rolePermissionClient,
            IUserPermissionClient userPermissionClient,
            IPasswordResetClient passwordResetClient,
            IGeneratePasswordResetKeyClient generatePasswordResetKeyClient,
            IValidatePasswordResetKeyClient validatePasswordResetKeyClient)
        {
            this.authenticationClient = authenticationClient;
            this.lockAccountClient = lockAccountClient;
            this.unlockAccountClient = unlockAccountClient;
            this.changePasswordClient = changePasswordClient;
            this.rolesClient = rolesClient;
            this.userRoleClient = userRoleClient;
            this.usersClient = usersClient;
            this.permissionsClient = permissionsClient;
            this.rolePermissionClient = rolePermissionClient;
            this.userPermissionClient = userPermissionClient;
            this.passwordResetClient = passwordResetClient;
            this.generatePasswordResetKeyClient = generatePasswordResetKeyClient;
            this.validatePasswordResetKeyClient = validatePasswordResetKeyClient;
        }

        public async Task<ResponseResult> ChangePassword(string userName, string oldPassword, string password, string passwordConfirm)
            =>
                await changePasswordClient.PutAsync(new ChangePasswordVM { UserName = userName, OldPassword = oldPassword, Password = password, PasswordConfirm = passwordConfirm });

        public async Task<ResponseResult> LockAccount(long userId) => await lockAccountClient.PutAsync(new LockAccountVM { UserId = userId });

        public async Task<ResponseResult> UnLockAccount(long userId) => await unlockAccountClient.PutAsync(new LockAccountVM { UserId = userId });

        public async Task<AuthenticationToken> LoginUser(string userName, string password)
            =>
                await authenticationClient.LoginAsync(new AuthenticateModel { Username = userName, Password = password });

        public async Task<ResponseResult> LogoutUser(string token)
        {
            try
            {
                await authenticationClient.LogoutAsync(new LogoutModel { Token = token });
            }
            catch (ApiException<ProblemDetails> exc)
            {
                return new ResponseResult { Success = true, Messages = new [] { exc.Response } };
            }
            catch (ApiException exc)
            {
                return new ResponseResult { Success = true, Messages = new[] { exc.Response } };
            }

            return new ResponseResult { Success = true };
        }

        #region Roles
        public async Task<ICollection<RoleVM>> GetRoles() => await rolesClient.GetAllAsync();

        public async Task<RoleVM> GetRole(long id) => await rolesClient.GetAsync(id);

        public async Task<ResponseResult> CreateRole(CreateRoleVM role) => await rolesClient.CreateAsync(role);

        public async Task<ResponseResult> UpdateRole(UpdateRoleVM role) => await rolesClient.UpdateAsync(role);

        public async Task<ResponseResult> DeleteRole(long id) => await rolesClient.DeleteAsync(id);
        #endregion

        #region UserRole
        public async Task<ResponseResult> AddUserToRole(UserRoleVM userRole) => await userRoleClient.AddUserToRoleAsync(userRole);

        public async Task<ResponseResult> RemoveUserFromRole(UserRoleVM userRole) => await userRoleClient.RemoveUserFromRoleAsync(userRole);
        #endregion

        #region Users
        public async Task<ICollection<UserVM>> GetUsers() => await usersClient.GetAllAsync();

        public async Task<UserVM> GetUser(long id) => await usersClient.GetAsync(id);

        public async Task<ResponseResult> CreateUser(CreateUserVM user) => await usersClient.CreateAsync(user);

        public async Task<ResponseResult> UpdateUser(UpdateUserVM user) => await usersClient.UpdateAsync(user);

        public async Task<ResponseResult> DeleteUser(long id) => await usersClient.DeleteAsync(id);
        #endregion

        #region Password Reset
        public async Task<PasswordResetKeyResponse> GeneratePasswordResetKey(GeneratePasswordResetKeyVM model) => await generatePasswordResetKeyClient.PostAsync(model);

        public async Task<ResponseResult> ValidatePasswordResetKey(ValidatePasswordResetKeyVM model) => await validatePasswordResetKeyClient.PostAsync(model);

        public async Task<ResponseResult> PasswordReset(PasswordResetVM model) => await passwordResetClient.PostAsync(model);
        #endregion

        #region Permissions
        public async Task<ICollection<PermissionVM>> GetPermissions() => await permissionsClient.GetAllAsync();

        public async Task<PermissionVM> GetPermission(long id) => await permissionsClient.GetAsync(id);

        public async Task<ResponseResult> CreatePermission(CreatePermissionVM permission) => await permissionsClient.CreateAsync(permission);

        public async Task<ResponseResult> UpdatePermission(UpdatePermissionVM permission) => await permissionsClient.UpdateAsync(permission);

        public async Task<ResponseResult> DeletePermission(long id) => await permissionsClient.DeleteAsync(id);
        #endregion

        #region Role Permission
        public async Task<ResponseResult> AddPermissionToRole(RolePermissionVM rolePermission) => await rolePermissionClient.CreateAsync(rolePermission);

        public async Task<ResponseResult> RemovePermissionFromRole(RolePermissionVM rolePermission) => await rolePermissionClient.DeleteAsync(rolePermission);
        #endregion

        #region User Permission
        public async Task<ResponseResult> AddPermissionToUser(UserPermissionVM userPermission) => await userPermissionClient.CreateAsync(userPermission);

        public async Task<ResponseResult> RemovePermissionFromUser(UserPermissionVM userPermission) => await userPermissionClient.DeleteAsync(userPermission);
        #endregion
    }
}
