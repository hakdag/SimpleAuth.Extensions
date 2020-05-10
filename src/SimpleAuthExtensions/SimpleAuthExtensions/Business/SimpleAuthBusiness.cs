using SimpleAuthExtensions.Service;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace SimpleAuthExtensions.Business
{
    public class SimpleAuthBusiness : ISimpleAuthBusiness
    {
        private readonly ILockAccountClient lockAccountClient;
        private readonly IUnLockAccountClient unlockAccountClient;
        private readonly IChangePasswordClient changePasswordClient;
        private readonly IRolesClient rolesClient;
        private readonly IUserRoleClient userRoleClient;
        private readonly IUsersClient usersClient;

        public SimpleAuthBusiness(
            ILockAccountClient lockAccountClient,
            IUnLockAccountClient unlockAccountClient,
            IChangePasswordClient changePasswordClient,
            IRolesClient rolesClient,
            IUserRoleClient userRoleClient,
            IUsersClient usersClient)
        {
            this.lockAccountClient = lockAccountClient;
            this.unlockAccountClient = unlockAccountClient;
            this.changePasswordClient = changePasswordClient;
            this.rolesClient = rolesClient;
            this.userRoleClient = userRoleClient;
            this.usersClient = usersClient;
        }

        public async Task<ResponseResult> ChangePassword(string userName, string oldPassword, string password, string passwordConfirm)
            =>
                await changePasswordClient.PutAsync(new ChangePasswordVM { UserName = userName, OldPassword = oldPassword, Password = password, PasswordConfirm = passwordConfirm });

        public async Task<ResponseResult> LockAccount(long userId) => await lockAccountClient.PutAsync(new LockAccountVM { UserId = userId });

        public async Task<ResponseResult> UnLockAccount(long userId) => await unlockAccountClient.PutAsync(new LockAccountVM { UserId = userId });

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
    }
}
