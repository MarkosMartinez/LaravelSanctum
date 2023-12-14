<?php

namespace App\Http\Controllers\Auth;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Hash;
use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;

class AuthController extends Controller
{
    

    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8'
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors());
        }

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password)
        ]);

        $token = $user->createToken('auth_token')->plainTextToken;

        return response()
            ->json(['data' => $user, 'access_token' => $token, 'token_type' => 'Bearer',]);
    }

    public function login(Request $request){
        if(!Auth::attempt($request->only('email','password'))){
            return response()->json(['message' => 'Error usuario o contraseña no valida', 401]);
        }

    $user = User::where('email', $request['email'])->firstOrFail();

    $token = $user->createToken('auth_token')->plainTextToken;

    return response()
        ->json([
            'message' => 'Usuario logueado correctamente!',
            'accessToken' => $token,
            'token_type' => 'Bearer',
            'user' => $user,
        ]);

    }

    public function logout(Request $request){
        auth()->user()->currentAccessToken()->delete();
        return response()
        ->json([
            'message' => 'Sesion cerrada correctamente!',
        ]);
    }

    public function logoutall(Request $request){
        auth()->user()->tokens()->delete();
        return response()
        ->json([
            'message' => 'Sesiones cerradas correctamente!',
        ]);
    }

}
