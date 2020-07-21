using SimpleAuthExtensions.Service;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace SimpleAuthExtensions.Business
{
    public interface ISimpleAuthBusiness
    {
        Task<ResponseResult> LockAccount(long userId);
        Task<ResponseResult> UnLockAccount(long userId);
        Task<ResponseResult> ChangePassword(string userName, string oldPassword, string password, string passwordConfirm);
        Task<ResponseResult> LogoutUser(string token);

        // Roles
        Task<ICollection<RoleVM>> GetRoles();
        Task<RoleVM> GetRole(long id);
        Task<ResponseResult> CreateRole(CreateRoleVM role);
        Task<ResponseResult> UpdateRole(UpdateRoleVM role);
        Task<ResponseResult> DeleteRole(long id);

        // UserRole
        Task<ResponseResult> AddUserToRole(UserRoleVM userRole);
        Task<ResponseResult> RemoveUserFromRole(UserRoleVM userRole);

        // Users
        Task<ICollection<UserVM>> GetUsers();
        Task<UserVM> GetUser(long id);
        Task<ResponseResult> CreateUser(CreateUserVM user);
        Task<ResponseResult> UpdateUser(UpdateUserVM user);
        Task<ResponseResult> DeleteUser(long id);

        // Password Reset
        Task<PasswordResetKeyResponse> GeneratePasswordResetKey(GeneratePasswordResetKeyVM model);
        Task<ResponseResult> ValidatePasswordResetKey(ValidatePasswordResetKeyVM model);
        Task<ResponseResult> PasswordReset(PasswordResetVM model);

        // User Role
        Task<ICollection<PermissionVM>> GetPermissions();
        Task<PermissionVM> GetPermission(long id);
        Task<ResponseResult> CreatePermission(CreatePermissionVM permission);
        Task<ResponseResult> UpdatePermission(UpdatePermissionVM permission);
        Task<ResponseResult> DeletePermission(long id);

        // Role Permission
        Task<ResponseResult> AddPermissionToRole(RolePermissionVM rolePermission);
        Task<ResponseResult> RemovePermissionFromRole(RolePermissionVM rolePermission);

        // User Permission
        Task<ResponseResult> AddPermissionToUser(UserPermissionVM userPermission);
        Task<ResponseResult> RemovePermissionFromUser(UserPermissionVM userPermission);
    }
}
